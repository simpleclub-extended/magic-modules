package tpgiamresource

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-google/google/tpgresource"
	transport_tpg "github.com/hashicorp/terraform-provider-google/google/transport"

	"google.golang.org/api/cloudresourcemanager/v1"
)

var IamPolicyBaseSchema = map[string]*schema.Schema{
	"policy_data": {
		Type:             schema.TypeString,
		Required:         true,
		DiffSuppressFunc: jsonPolicyDiffSuppress,
		ValidateFunc:     validateIamPolicy,
	},
	"etag": {
		Type:     schema.TypeString,
		Computed: true,
	},
	"default_binding_behaviour": {
		Type:     schema.TypeString,
		Optional: true,
		Default:  "override",
		Description: `Specifies how Google-managed service agent bindings are handled. ` +
			`"override" (default) replaces the entire IAM policy, removing any bindings not in policy_data. ` +
			`"ignore" preserves existing service agent bindings, only managing non-service-agent bindings.`,
		ValidateFunc: validation.StringInSlice([]string{"override", "ignore"}, false),
	},
}

func iamPolicyImport(resourceIdParser ResourceIdParserFunc) schema.StateFunc {
	return func(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
		if resourceIdParser == nil {
			return nil, errors.New("Import not supported for this IAM resource.")
		}
		config := m.(*transport_tpg.Config)
		err := resourceIdParser(d, config)
		if err != nil {
			return nil, err
		}
		return []*schema.ResourceData{d}, nil
	}
}

func ResourceIamPolicy(parentSpecificSchema map[string]*schema.Schema, newUpdaterFunc NewResourceIamUpdaterFunc, resourceIdParser ResourceIdParserFunc, options ...func(*IamSettings)) *schema.Resource {
	settings := NewIamSettings(options...)
	createTimeOut := time.Duration(settings.CreateTimeOut) * time.Minute

	resourceSchema := &schema.Resource{
		Create: ResourceIamPolicyCreate(newUpdaterFunc),
		Read:   ResourceIamPolicyRead(newUpdaterFunc),
		Update: ResourceIamPolicyUpdate(newUpdaterFunc),
		Delete: ResourceIamPolicyDelete(newUpdaterFunc),

		// if non-empty, this will be used to send a deprecation message when the
		// resource is used.
		DeprecationMessage: settings.DeprecationMessage,

		Schema:         tpgresource.MergeSchemas(IamPolicyBaseSchema, parentSpecificSchema),
		SchemaVersion:  settings.SchemaVersion,
		StateUpgraders: settings.StateUpgraders,
		Importer: &schema.ResourceImporter{
			State: iamPolicyImport(resourceIdParser),
		},
		UseJSONNumber: true,
	}
	if createTimeOut > 0 {
		resourceSchema.Timeouts = &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(createTimeOut),
		}
	}
	return resourceSchema
}

func ResourceIamPolicyCreate(newUpdaterFunc NewResourceIamUpdaterFunc) schema.CreateFunc {
	return func(d *schema.ResourceData, meta interface{}) error {
		config := meta.(*transport_tpg.Config)

		updater, err := newUpdaterFunc(d, config)
		if err != nil {
			return err
		}

		if err = setIamPolicyData(d, updater); err != nil {
			return err
		}

		d.SetId(updater.GetResourceId())
		return ResourceIamPolicyRead(newUpdaterFunc)(d, meta)
	}
}

// getDefaultBindingBehaviour returns the configured default_binding_behaviour,
// defaulting to "override" if not set.
func getDefaultBindingBehaviour(d *schema.ResourceData) string {
	if v, ok := d.GetOk("default_binding_behaviour"); ok {
		return v.(string)
	}
	return "override"
}

func ResourceIamPolicyRead(newUpdaterFunc NewResourceIamUpdaterFunc) schema.ReadFunc {
	return func(d *schema.ResourceData, meta interface{}) error {
		config := meta.(*transport_tpg.Config)

		updater, err := newUpdaterFunc(d, config)
		if err != nil {
			return err
		}

		policy, err := iamPolicyReadWithRetry(updater)
		if err != nil {
			return transport_tpg.HandleNotFoundError(err, d, fmt.Sprintf("Resource %q with IAM Policy", updater.DescribeResource()))
		}

		if err := d.Set("etag", policy.Etag); err != nil {
			return fmt.Errorf("Error setting etag: %s", err)
		}

		// In "ignore" mode, filter out service agent bindings from state so they
		// don't appear in diffs and the user only sees non-service-agent bindings.
		if getDefaultBindingBehaviour(d) == "ignore" {
			policy = &cloudresourcemanager.Policy{
				AuditConfigs: policy.AuditConfigs,
				Bindings:     FilterOutServiceAgentMembers(policy.Bindings),
				Etag:         policy.Etag,
				Version:      policy.Version,
			}
		}

		if err := d.Set("policy_data", marshalIamPolicy(policy)); err != nil {
			return fmt.Errorf("Error setting policy_data: %s", err)
		}

		return nil
	}
}

func ResourceIamPolicyUpdate(newUpdaterFunc NewResourceIamUpdaterFunc) schema.UpdateFunc {
	return func(d *schema.ResourceData, meta interface{}) error {
		config := meta.(*transport_tpg.Config)

		updater, err := newUpdaterFunc(d, config)
		if err != nil {
			return err
		}

		if d.HasChange("policy_data") || d.HasChange("default_binding_behaviour") {
			if err := setIamPolicyData(d, updater); err != nil {
				return err
			}
		}

		return ResourceIamPolicyRead(newUpdaterFunc)(d, meta)
	}
}

func ResourceIamPolicyDelete(newUpdaterFunc NewResourceIamUpdaterFunc) schema.DeleteFunc {
	return func(d *schema.ResourceData, meta interface{}) error {
		config := meta.(*transport_tpg.Config)

		updater, err := newUpdaterFunc(d, config)
		if err != nil {
			return err
		}

		pol := &cloudresourcemanager.Policy{}
		if v, ok := d.GetOk("etag"); ok {
			pol.Etag = v.(string)
		}
		pol.Version = IamPolicyVersion

		// In "ignore" mode, preserve the existing service agent bindings rather
		// than wiping the entire policy.
		if getDefaultBindingBehaviour(d) == "ignore" {
			existingPolicy, err := updater.GetResourceIamPolicy()
			if err != nil {
				return fmt.Errorf("Error reading IAM policy for %s during delete: %s", updater.DescribeResource(), err)
			}
			pol.Bindings = ExtractServiceAgentMembers(existingPolicy.Bindings)
			pol.AuditConfigs = existingPolicy.AuditConfigs
		}

		err = updater.SetResourceIamPolicy(pol)
		if err != nil {
			return err
		}

		return nil
	}
}

func setIamPolicyData(d *schema.ResourceData, updater ResourceIamUpdater) error {
	policy, err := unmarshalIamPolicy(d.Get("policy_data").(string))
	if err != nil {
		return fmt.Errorf("'policy_data' is not valid for %s: %s", updater.DescribeResource(), err)
	}
	policy.Version = IamPolicyVersion

	// In "ignore" mode, merge the user's bindings with existing service agent
	// bindings so that service agents are preserved.
	if getDefaultBindingBehaviour(d) == "ignore" {
		existingPolicy, err := updater.GetResourceIamPolicy()
		if err != nil {
			return fmt.Errorf("Error reading existing IAM policy for %s: %s", updater.DescribeResource(), err)
		}
		serviceAgentBindings := ExtractServiceAgentMembers(existingPolicy.Bindings)
		policy.Bindings = MergeBindings(append(policy.Bindings, serviceAgentBindings...))
	}

	err = updater.SetResourceIamPolicy(policy)
	if err != nil {
		return err
	}

	return nil
}

func marshalIamPolicy(policy *cloudresourcemanager.Policy) string {
	pdBytes, _ := json.Marshal(&cloudresourcemanager.Policy{
		AuditConfigs: policy.AuditConfigs,
		Bindings:     policy.Bindings,
	})
	return string(pdBytes)
}

func unmarshalIamPolicy(policyData string) (*cloudresourcemanager.Policy, error) {
	policy := &cloudresourcemanager.Policy{}
	if err := json.Unmarshal([]byte(policyData), policy); err != nil {
		return nil, fmt.Errorf("Could not unmarshal policy data %s:\n%s", policyData, err)
	}
	return policy, nil
}

func validateIamPolicy(i interface{}, k string) (s []string, es []error) {
	if policy, err := unmarshalIamPolicy(i.(string)); err != nil {
		es = append(es, err)
	} else {
		for i, binding := range policy.Bindings {
			for j, member := range binding.Members {
				_, memberErrors := validateIAMMember(member, fmt.Sprintf("bindings.%d.members.%d", i, j))
				es = append(es, memberErrors...)
			}
		}
	}
	return
}
