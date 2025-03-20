/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package sdkms

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "strings"
    "github.com/pkg/errors"
)

// AWS KMS resources are hosted in multiple locations world-wide and
// each AWS Region is a separate geographic area
// https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.RegionsAndAvailabilityZones.html
type AwskmsRegion string

// List of supported AwskmsRegion values
const (
    AwskmsRegionUsEast1 AwskmsRegion = "us-east-1"
    AwskmsRegionUsEast2 AwskmsRegion = "us-east-2"
    AwskmsRegionUsWest1 AwskmsRegion = "us-west-1"
    AwskmsRegionUsWest2 AwskmsRegion = "us-west-2"
    AwskmsRegionAfSouth1 AwskmsRegion = "af-south-1"
    AwskmsRegionApEast1 AwskmsRegion = "ap-east-1"
    AwskmsRegionApSoutheast3 AwskmsRegion = "ap-southeast-3"
    AwskmsRegionApSoutheast4 AwskmsRegion = "ap-southeast-4"
    AwskmsRegionApSouth1 AwskmsRegion = "ap-south-1"
    AwskmsRegionApSouth2 AwskmsRegion = "ap-south-2"
    AwskmsRegionApNortheast3 AwskmsRegion = "ap-northeast-3"
    AwskmsRegionApNortheast2 AwskmsRegion = "ap-northeast-2"
    AwskmsRegionApSoutheast1 AwskmsRegion = "ap-southeast-1"
    AwskmsRegionApSoutheast2 AwskmsRegion = "ap-southeast-2"
    AwskmsRegionApNortheast1 AwskmsRegion = "ap-northeast-1"
    AwskmsRegionCaCentral1 AwskmsRegion = "ca-central-1"
    AwskmsRegionCaWest1 AwskmsRegion = "ca-west-1"
    AwskmsRegionEuCentral1 AwskmsRegion = "eu-central-1"
    AwskmsRegionEuCentral2 AwskmsRegion = "eu-central-2"
    AwskmsRegionEuWest1 AwskmsRegion = "eu-west-1"
    AwskmsRegionEuWest2 AwskmsRegion = "eu-west-2"
    AwskmsRegionEuSouth1 AwskmsRegion = "eu-south-1"
    AwskmsRegionEuSouth2 AwskmsRegion = "eu-south-2"
    AwskmsRegionEuWest3 AwskmsRegion = "eu-west-3"
    AwskmsRegionEuNorth1 AwskmsRegion = "eu-north-1"
    AwskmsRegionMeSouth1 AwskmsRegion = "me-south-1"
    AwskmsRegionMeCentral1 AwskmsRegion = "me-central-1"
    AwskmsRegionSaEast1 AwskmsRegion = "sa-east-1"
    AwskmsRegionUsGovEast1 AwskmsRegion = "us-gov-east-1"
    AwskmsRegionUsGovWest1 AwskmsRegion = "us-gov-west-1"
    AwskmsRegionIlCentral1 AwskmsRegion = "il-central-1"
)

// Specifies the AWS service. Only `kms` is supported for now.
type AwskmsService string

// List of supported AwskmsService values
const (
    AwskmsServiceKms AwskmsService = "kms"
    AwskmsServiceKmsFips AwskmsService = "kms-fips"
)

type AzureAuthConfig struct {
    ClientSecret *AzureAuthConfigClientSecret
    TokenAuthConfig *AzureAuthConfigTokenAuthConfig
}
type AzureAuthConfigClientSecret struct {
    ClientSecret ZeroizedString `json:"client_secret"`
}
type AzureAuthConfigTokenAuthConfig struct {
    ClientCert ZeroizedBlob `json:"client_cert"`
    ClientKey ZeroizedBlob `json:"client_key"`
}
func (x AzureAuthConfig) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "AzureAuthConfig", 
                  []bool{ x.ClientSecret != nil,
                  x.TokenAuthConfig != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.ClientSecret != nil:
        b, err := json.Marshal(x.ClientSecret)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["mode"] = "client_secret"
    case x.TokenAuthConfig != nil:
        b, err := json.Marshal(x.TokenAuthConfig)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["mode"] = "token_auth_config"
    }
    return json.Marshal(m)
}
func (x *AzureAuthConfig) UnmarshalJSON(data []byte) error {
    x.ClientSecret = nil
    x.TokenAuthConfig = nil
    var h struct {
        Tag string `json:"mode"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid AzureAuthConfig")
    }
    switch h.Tag {
    case "client_secret":
        var clientSecret AzureAuthConfigClientSecret
        if err := json.Unmarshal(data, &clientSecret); err != nil {
            return err
        }
        x.ClientSecret = &clientSecret
    case "token_auth_config":
        var tokenAuthConfig AzureAuthConfigTokenAuthConfig
        if err := json.Unmarshal(data, &tokenAuthConfig); err != nil {
            return err
        }
        x.TokenAuthConfig = &tokenAuthConfig
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

// Types of Azure Key Vault based on the protection level.
type AzureKeyVaultType string

// List of supported AzureKeyVaultType values
const (
    // Software-protected
    AzureKeyVaultTypeStandard AzureKeyVaultType = "STANDARD"
    // HSM-protected (with Premium SKU)
    AzureKeyVaultTypePremium AzureKeyVaultType = "PREMIUM"
    // Azure Managed HSM
    AzureKeyVaultTypeManaged AzureKeyVaultType = "MANAGED"
)

// The set of endpoints to use when connecting with Azure cloud.
//
// Today, only Azure global and Azure Government cloud endpoints are supported,
// and they cannot be mixed together. The Azure global endpoints are
// - `management`: management.azure.com
// - `key_vault`: vault.azure.net
// - `key_vault_managed_hsm`: managedhsm.azure.net
// - `iam`: login.microsoftonline.com
//
// and the Azure Government endpoints are
// - `management`: management.usgovcloudapi.net
// - `key_vault`: vault.usgovcloudapi.net
// - `key_vault_managed_hsm`: managedhsm.usgovcloudapi.net
// - `iam`: login.microsoftonline.us
//
// (In the future, this restriction may be relaxed to support custom clouds.)
type AzureServiceEndpoints struct {
    // The API endpoint for managing Azure APIs and resources.
    Management string `json:"management"`
    // The API endpoint for Azure Key Vault (for Standard and Premium SKUs).
    KeyVault string `json:"key_vault"`
    // The API endpoint for Azure Key Vault Managed HSM.
    KeyVaultManagedHsm string `json:"key_vault_managed_hsm"`
    // The API endpoint for Azure AD (and authentication).
    Iam string `json:"iam"`
}

type CheckHmgRequest struct {
    // The ID of the hmg configuration in the group.
    ID *UUID `json:"id,omitempty"`
    Config *HmgConfig `json:"config,omitempty"`
}

type GcpKeyRingConfig struct {
    // Email for the service account to be used.
    ServiceAccountEmail string `json:"service_account_email"`
    // The project ID is a unique identifier for a project
    ProjectID string `json:"project_id"`
    // For a given project in GCP KMS, resources can be created in one of many locations.
    // These represent the geographical regions where a resource is stored and can be accessed.
    // A key's location impacts the performance of applications using the key.
    // https://cloud.google.com/kms/docs/locations
    Location string `json:"location"`
    // A key ring organizes keys in a specific GCP location and allows you to manage
    // access control on groups of keys.
    // https://cloud.google.com/kms/docs/resource-hierarchy#key_rings
    KeyRing *string `json:"key_ring,omitempty"`
    // Private component of the service account key pair that can be
    // obtained from the GCP cloud console. It is used to authenticate
    // the requests made by DSM to the GCP cloud.
    PrivateKey *ZeroizedBlob `json:"private_key,omitempty"`
}

// Information about a group's recent scans.
type GetAllHmgScansResponse struct {
    // List of all tracked scans, from newest to oldest.
    Items []Scan `json:"items"`
}

type Group struct {
    AcctID UUID `json:"acct_id"`
    ApprovalPolicy *GroupApprovalPolicy `json:"approval_policy,omitempty"`
    // Settings for automatic key scanning. For now, this is only available for DSM-backed groups.
    AutoScan *AutoScanSettings `json:"auto_scan,omitempty"`
    ClientConfigurations ClientConfigurations `json:"client_configurations"`
    CreatedAt Time `json:"created_at"`
    Creator Principal `json:"creator"`
    CryptographicPolicy *CryptographicPolicy `json:"cryptographic_policy,omitempty"`
    CustodianPolicy *QuorumPolicy `json:"custodian_policy,omitempty"`
    CustomMetadata *map[string]string `json:"custom_metadata,omitempty"`
    Description *string `json:"description,omitempty"`
    // Export policy that applies to exportable sobjects (ones with `EXPORT` key op) in the group.
    ExportPolicy *ExportPolicy `json:"export_policy,omitempty"`
    // Key Access Justifications for GCP EKM.
    // For more details: https://cloud.google.com/cloud-provider-access-management/key-access-justifications/docs/overview
    GoogleAccessReasonPolicy *GoogleAccessReasonPolicy `json:"google_access_reason_policy,omitempty"`
    GroupID UUID `json:"group_id"`
    Hmg *map[UUID]HmgConfig `json:"hmg,omitempty"`
    // The `HmgRedundancyScheme` to set for the group. If unset, the backend will assign no particular meaning to the `hsm_order` fields of the group's `HmgConfig`s, and may error if it cannot connect to the external HSMs or DSM nodes specified in one of the `HmgConfig`s.
    // 
    // When creating the group, the value should either be an `HmgRedundancyScheme`, or omitted entirely. When updating the group, there are three choices:
    // - A new value can be set by providing an `HmgRedundancyScheme`.
    // - The string "remove" can be specified to unset the field.
    // - Simply leaving the field blank leaves the field unchanged.
    HmgRedundancy *HmgRedundancyScheme `json:"hmg_redundancy,omitempty"`
    HmgSegregation *bool `json:"hmg_segregation,omitempty"`
    HmgSync *bool `json:"hmg_sync,omitempty"`
    KeyHistoryPolicy *KeyHistoryPolicy `json:"key_history_policy,omitempty"`
    KeyMetadataPolicy *KeyMetadataPolicy `json:"key_metadata_policy,omitempty"`
    Name string `json:"name"`
    // Name of an AES key from another group. The key will be used to encrypt the key material of all keys in this group
    WrappingKeyName *WrappingKeyName `json:"wrapping_key_name,omitempty"`
}

// Group approval policy.
type GroupApprovalPolicy struct {
    Policy QuorumPolicy `json:"policy"`
    // Deprecated, left this for backward compatibility.
    // When this is true, manage operations on security objects require approval.
    ProtectManageOperations *bool `json:"protect_manage_operations,omitempty"`
    // Use QuorumGroupPermissions to represent operations that require approval.
    ProtectPermissions *QuorumGroupPermissions `json:"protect_permissions,omitempty"`
    // When this is true, cryptographic operations on security objects require approval.
    ProtectCryptoOperations *bool `json:"protect_crypto_operations,omitempty"`
}
func (x GroupApprovalPolicy) MarshalJSON() ([]byte, error) {
    m := make(map[string]interface{})
    { // x.Policy is flattened
        b, err := json.Marshal(&x.Policy)
        if err != nil {
            return nil, err
        }
        f := make(map[string]interface{})
        if err := json.Unmarshal(b, &f); err != nil {
            return nil, err
        }
        for k, v := range f {
            m[k] = v
        }
    }
    if x.ProtectManageOperations != nil {
        m["protect_manage_operations"] = x.ProtectManageOperations
    }
    if x.ProtectPermissions != nil {
        m["protect_permissions"] = x.ProtectPermissions
    }
    if x.ProtectCryptoOperations != nil {
        m["protect_crypto_operations"] = x.ProtectCryptoOperations
    }
    return json.Marshal(&m)
}
func (x *GroupApprovalPolicy) UnmarshalJSON(data []byte) error {
    if err := json.Unmarshal(data, &x.Policy); err != nil {
        return err
    }
    var r struct {
    ProtectManageOperations *bool `json:"protect_manage_operations,omitempty"`
    ProtectPermissions *QuorumGroupPermissions `json:"protect_permissions,omitempty"`
    ProtectCryptoOperations *bool `json:"protect_crypto_operations,omitempty"`
    }
    if err := json.Unmarshal(data, &r); err != nil {
        return err
    }
    x.ProtectManageOperations = r.ProtectManageOperations
    x.ProtectPermissions = r.ProtectPermissions
    x.ProtectCryptoOperations = r.ProtectCryptoOperations
    return nil
}

type GroupRequest struct {
    AddHmg *[]HmgConfig `json:"add_hmg,omitempty"`
    ApprovalPolicy *GroupApprovalPolicy `json:"approval_policy,omitempty"`
    // Settings for automatic key scanning. For now, this is only available for DSM-backed groups.
    AutoScan *Removable[AutoScanSettings] `json:"auto_scan,omitempty"`
    ClientConfigurations *ClientConfigurationsRequest `json:"client_configurations,omitempty"`
    CryptographicPolicy *Removable[CryptographicPolicy] `json:"cryptographic_policy,omitempty"`
    CustodianPolicy *QuorumPolicy `json:"custodian_policy,omitempty"`
    CustomMetadata *map[string]string `json:"custom_metadata,omitempty"`
    DelHmg *[]UUID `json:"del_hmg,omitempty"`
    Description *string `json:"description,omitempty"`
    // Export policy that applies to exportable sobjects (ones with `EXPORT` key op) in the group.
    ExportPolicy *ExportPolicy `json:"export_policy,omitempty"`
    // Key Access Justifications for GCP EKM.
    // For more details: https://cloud.google.com/cloud-provider-access-management/key-access-justifications/docs/overview
    GoogleAccessReasonPolicy *Removable[GoogleAccessReasonPolicy] `json:"google_access_reason_policy,omitempty"`
    // The `HmgRedundancyScheme` to set for the group. If unset, the backend will assign no particular meaning to the `hsm_order` fields of the group's `HmgConfig`s, and may error if it cannot connect to the external HSMs or DSM nodes specified in one of the `HmgConfig`s.
    // 
    // When creating the group, the value should either be an `HmgRedundancyScheme`, or omitted entirely. When updating the group, there are three choices:
    // - A new value can be set by providing an `HmgRedundancyScheme`.
    // - The string "remove" can be specified to unset the field.
    // - Simply leaving the field blank leaves the field unchanged.
    HmgRedundancy *Removable[HmgRedundancyScheme] `json:"hmg_redundancy,omitempty"`
    HmgSegregation *bool `json:"hmg_segregation,omitempty"`
    HmgSync *bool `json:"hmg_sync,omitempty"`
    KeyHistoryPolicy *Removable[KeyHistoryPolicy] `json:"key_history_policy,omitempty"`
    KeyMetadataPolicy *Removable[KeyMetadataPolicy] `json:"key_metadata_policy,omitempty"`
    ModHmg *map[UUID]HmgConfig `json:"mod_hmg,omitempty"`
    Name *string `json:"name,omitempty"`
    // Name of an AES key from another group. The key will be used to encrypt the key material of all keys in this group
    WrappingKeyName *WrappingKeyName `json:"wrapping_key_name,omitempty"`
}

type HmgConfig struct {
    Ncipher *HmgConfigNcipher
    Safenet *HmgConfigSafenet
    AwsCloudHsm *HmgConfigAwsCloudHsm
    AwsKms *HmgConfigAwsKms
    Fortanix *HmgConfigFortanix
    FortanixFipsCluster *HmgConfigFortanixFipsCluster
    AzureKeyVault *HmgConfigAzureKeyVault
    GcpKeyRing *GcpKeyRingConfig
}
type HmgConfigNcipher struct {
    URL string `json:"url"`
    TLS TlsConfig `json:"tls"`
    Slot uint `json:"slot"`
    Pin *ZeroizedString `json:"pin,omitempty"`
    // The priority of this `HmgConfig`. This is used when a group is
    // configured with an `HmgRedundancyScheme`, and is otherwise
    // unused. (See the docs for `HmgRedundancyScheme` for more
    // information about the interpretation of this field.)
    HsmOrder *int32 `json:"hsm_order,omitempty"`
}
type HmgConfigSafenet struct {
    URL string `json:"url"`
    TLS TlsConfig `json:"tls"`
    Slot uint `json:"slot"`
    Pin *ZeroizedString `json:"pin,omitempty"`
    // The priority of this `HmgConfig`. This is used when a group is
    // configured with an `HmgRedundancyScheme`, and is otherwise
    // unused. (See the docs for `HmgRedundancyScheme` for more
    // information about the interpretation of this field.)
    HsmOrder *int32 `json:"hsm_order,omitempty"`
}
type HmgConfigAwsCloudHsm struct {
    URL string `json:"url"`
    TLS TlsConfig `json:"tls"`
    Slot uint `json:"slot"`
    Pin *ZeroizedString `json:"pin,omitempty"`
    // The priority of this `HmgConfig`. This is used when a group is
    // configured with an `HmgRedundancyScheme`, and is otherwise
    // unused. (See the docs for `HmgRedundancyScheme` for more
    // information about the interpretation of this field.)
    HsmOrder *int32 `json:"hsm_order,omitempty"`
}
type HmgConfigAwsKms struct {
    URL string `json:"url"`
    TLS TlsConfig `json:"tls"`
    AccessKey *string `json:"access_key,omitempty"`
    SecretKey *ZeroizedString `json:"secret_key,omitempty"`
    Region *AwskmsRegion `json:"region,omitempty"`
    Service *AwskmsService `json:"service,omitempty"`
    AccountID *string `json:"account_id,omitempty"`
}
type HmgConfigFortanix struct {
    URL string `json:"url"`
    TLS TlsConfig `json:"tls"`
    Pin *ZeroizedString `json:"pin,omitempty"`
}
type HmgConfigFortanixFipsCluster struct {
    URL string `json:"url"`
    TLS TlsConfig `json:"tls"`
    Pin *ZeroizedString `json:"pin,omitempty"`
    Credentials *[]ZeroizedString `json:"credentials,omitempty"`
    // The priority of this `HmgConfig`. This is used when a group is
    // configured with an `HmgRedundancyScheme`, and is otherwise
    // unused. (See the docs for `HmgRedundancyScheme` for more
    // information about the interpretation of this field.)
    HsmOrder *int32 `json:"hsm_order,omitempty"`
}
type HmgConfigAzureKeyVault struct {
    URL string `json:"url"`
    TLS TlsConfig `json:"tls"`
    AuthConfig AzureAuthConfig `json:"auth_config"`
    // Deprecated, left this for backward compatibility. Should use auth_config.
    SecretKey *ZeroizedString `json:"secret_key,omitempty"`
    // A tenant ID is a unique way to identify an Azure AD instance
    // within an Azure subscription.
    TenantID UUID `json:"tenant_id"`
    // The client ID is the unique Application ID assigned
    // to your app by Azure AD when the app was registered.
    ClientID UUID `json:"client_id"`
    // A subscription ID is a unique alphanumeric string
    // that identifies your Azure subscription.
    SubscriptionID UUID `json:"subscription_id"`
    // Specifies the type of key vault to be configured.
    KeyVaultType *AzureKeyVaultType `json:"key_vault_type,omitempty"`
    // Which Azure endpoints to use. If not specified upon group creation or
    // update, endpoints for (ordinary) Azure global cloud will be used.
    Endpoints *AzureServiceEndpoints `json:"endpoints,omitempty"`
}
func (x HmgConfig) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "HmgConfig", 
                  []bool{ x.Ncipher != nil,
                  x.Safenet != nil,
                  x.AwsCloudHsm != nil,
                  x.AwsKms != nil,
                  x.Fortanix != nil,
                  x.FortanixFipsCluster != nil,
                  x.AzureKeyVault != nil,
                  x.GcpKeyRing != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.Ncipher != nil:
        b, err := json.Marshal(x.Ncipher)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["kind"] = "Ncipher"
    case x.Safenet != nil:
        b, err := json.Marshal(x.Safenet)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["kind"] = "Safenet"
    case x.AwsCloudHsm != nil:
        b, err := json.Marshal(x.AwsCloudHsm)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["kind"] = "AwsCloudHsm"
    case x.AwsKms != nil:
        b, err := json.Marshal(x.AwsKms)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["kind"] = "AwsKms"
    case x.Fortanix != nil:
        b, err := json.Marshal(x.Fortanix)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["kind"] = "Fortanix"
    case x.FortanixFipsCluster != nil:
        b, err := json.Marshal(x.FortanixFipsCluster)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["kind"] = "FortanixFipsCluster"
    case x.AzureKeyVault != nil:
        b, err := json.Marshal(x.AzureKeyVault)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["kind"] = "AzureKeyVault"
    case x.GcpKeyRing != nil:
        b, err := json.Marshal(x.GcpKeyRing)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["kind"] = "GcpKeyRing"
    }
    return json.Marshal(m)
}
func (x *HmgConfig) UnmarshalJSON(data []byte) error {
    x.Ncipher = nil
    x.Safenet = nil
    x.AwsCloudHsm = nil
    x.AwsKms = nil
    x.Fortanix = nil
    x.FortanixFipsCluster = nil
    x.AzureKeyVault = nil
    x.GcpKeyRing = nil
    var h struct {
        Tag string `json:"kind"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid HmgConfig")
    }
    switch h.Tag {
    case "Ncipher":
        var ncipher HmgConfigNcipher
        if err := json.Unmarshal(data, &ncipher); err != nil {
            return err
        }
        x.Ncipher = &ncipher
    case "Safenet":
        var safenet HmgConfigSafenet
        if err := json.Unmarshal(data, &safenet); err != nil {
            return err
        }
        x.Safenet = &safenet
    case "AwsCloudHsm":
        var awsCloudHsm HmgConfigAwsCloudHsm
        if err := json.Unmarshal(data, &awsCloudHsm); err != nil {
            return err
        }
        x.AwsCloudHsm = &awsCloudHsm
    case "AwsKms":
        var awsKms HmgConfigAwsKms
        if err := json.Unmarshal(data, &awsKms); err != nil {
            return err
        }
        x.AwsKms = &awsKms
    case "Fortanix":
        var fortanix HmgConfigFortanix
        if err := json.Unmarshal(data, &fortanix); err != nil {
            return err
        }
        x.Fortanix = &fortanix
    case "FortanixFipsCluster":
        var fortanixFipsCluster HmgConfigFortanixFipsCluster
        if err := json.Unmarshal(data, &fortanixFipsCluster); err != nil {
            return err
        }
        x.FortanixFipsCluster = &fortanixFipsCluster
    case "AzureKeyVault":
        var azureKeyVault HmgConfigAzureKeyVault
        if err := json.Unmarshal(data, &azureKeyVault); err != nil {
            return err
        }
        x.AzureKeyVault = &azureKeyVault
    case "GcpKeyRing":
        var gcpKeyRing GcpKeyRingConfig
        if err := json.Unmarshal(data, &gcpKeyRing); err != nil {
            return err
        }
        x.GcpKeyRing = &gcpKeyRing
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

// The scheme for determining how multiple `HmgConfig`s on a group
// should behave. If not specified, the backend will go through
// the list in random order, and use the first `HmgConfig` that works.
type HmgRedundancyScheme string

// List of supported HmgRedundancyScheme values
const (
    // Go through the list of `HmgConfig`s in the order specified in
    // each one's `hsm_order` field. Smaller numbers indicate higher
    // priority; e.g., "1" takes precedence over "3", and "-4" takes
    // precedence over "-1".
    HmgRedundancySchemePriorityFailover HmgRedundancyScheme = "PriorityFailover"
)

type KeyVault struct {
    ID string `json:"id"`
    Name string `json:"name"`
    VaultType AzureKeyVaultType `json:"vault_type"`
    Location string `json:"location"`
    Tags *map[string]string `json:"tags,omitempty"`
    Retention *uint32 `json:"retention,omitempty"`
    URI string `json:"uri"`
}

// The response of the get all groups API
type ListGroupsResponse struct {
    // A response that includes metadata
    WithMetadata *ListGroupsResponseWithMetadata
    // A response that omits metadata
    WithoutMetadata *[]Group
}
// A response that includes metadata
type ListGroupsResponseWithMetadata struct {
    // The list of groups satisfying the request
    Items []Group `json:"items"`
    // The metadata associated with the response
    Metadata CollectionMetadata `json:"metadata"`
}
func (x ListGroupsResponse) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "ListGroupsResponse", 
                  []bool{ x.WithMetadata != nil,
                  x.WithoutMetadata != nil });
                  err != nil {
        return nil, err
    }
    if x.WithMetadata != nil {
        return json.Marshal(x.WithMetadata)
    }
    if x.WithoutMetadata != nil {
        return json.Marshal(x.WithoutMetadata)
    }
    panic("unreachable")
}
func (x *ListGroupsResponse) UnmarshalJSON(data []byte) error {
    x.WithMetadata = nil
    x.WithoutMetadata = nil
    var withMetadata ListGroupsResponseWithMetadata
    if err := json.Unmarshal(data, &withMetadata); err == nil {
        x.WithMetadata = &withMetadata
        return nil
    }
    var withoutMetadata []Group
    if err := json.Unmarshal(data, &withoutMetadata); err == nil {
        x.WithoutMetadata = &withoutMetadata
        return nil
    }
    return errors.Errorf("not a valid ListGroupsResponse")
}

// Subset of GroupPermissions to represent GroupPermissions flags in use
type QuorumGroupPermissions uint64

// List of supported QuorumGroupPermissions values
const (
    QuorumGroupPermissionsGetSobjects QuorumGroupPermissions = 1 << iota
    QuorumGroupPermissionsRotateSobjects
    QuorumGroupPermissionsRevokeSobjects
    QuorumGroupPermissionsRevertSobjects
    QuorumGroupPermissionsDeleteKeyMaterial
    QuorumGroupPermissionsDeleteSobjects
    QuorumGroupPermissionsDestroySobjects
    QuorumGroupPermissionsMoveSobjects
    QuorumGroupPermissionsCreateSobjects
    QuorumGroupPermissionsUpdateSobjectsProfile
    QuorumGroupPermissionsUpdateSobjectsEnabledState
    QuorumGroupPermissionsUpdateSobjectPolicies
    QuorumGroupPermissionsActivateSobjects
    QuorumGroupPermissionsUpdateKeyOps
)

// MarshalJSON converts QuorumGroupPermissions to an array of strings
func (x QuorumGroupPermissions) MarshalJSON() ([]byte, error) {
    s := make([]string, 0)
    if x & QuorumGroupPermissionsGetSobjects == QuorumGroupPermissionsGetSobjects {
        s = append(s, "GET_SOBJECTS")
    }
    if x & QuorumGroupPermissionsRotateSobjects == QuorumGroupPermissionsRotateSobjects {
        s = append(s, "ROTATE_SOBJECTS")
    }
    if x & QuorumGroupPermissionsRevokeSobjects == QuorumGroupPermissionsRevokeSobjects {
        s = append(s, "REVOKE_SOBJECTS")
    }
    if x & QuorumGroupPermissionsRevertSobjects == QuorumGroupPermissionsRevertSobjects {
        s = append(s, "REVERT_SOBJECTS")
    }
    if x & QuorumGroupPermissionsDeleteKeyMaterial == QuorumGroupPermissionsDeleteKeyMaterial {
        s = append(s, "DELETE_KEY_MATERIAL")
    }
    if x & QuorumGroupPermissionsDeleteSobjects == QuorumGroupPermissionsDeleteSobjects {
        s = append(s, "DELETE_SOBJECTS")
    }
    if x & QuorumGroupPermissionsDestroySobjects == QuorumGroupPermissionsDestroySobjects {
        s = append(s, "DESTROY_SOBJECTS")
    }
    if x & QuorumGroupPermissionsMoveSobjects == QuorumGroupPermissionsMoveSobjects {
        s = append(s, "MOVE_SOBJECTS")
    }
    if x & QuorumGroupPermissionsCreateSobjects == QuorumGroupPermissionsCreateSobjects {
        s = append(s, "CREATE_SOBJECTS")
    }
    if x & QuorumGroupPermissionsUpdateSobjectsProfile == QuorumGroupPermissionsUpdateSobjectsProfile {
        s = append(s, "UPDATE_SOBJECTS_PROFILE")
    }
    if x & QuorumGroupPermissionsUpdateSobjectsEnabledState == QuorumGroupPermissionsUpdateSobjectsEnabledState {
        s = append(s, "UPDATE_SOBJECTS_ENABLED_STATE")
    }
    if x & QuorumGroupPermissionsUpdateSobjectPolicies == QuorumGroupPermissionsUpdateSobjectPolicies {
        s = append(s, "UPDATE_SOBJECT_POLICIES")
    }
    if x & QuorumGroupPermissionsActivateSobjects == QuorumGroupPermissionsActivateSobjects {
        s = append(s, "ACTIVATE_SOBJECTS")
    }
    if x & QuorumGroupPermissionsUpdateKeyOps == QuorumGroupPermissionsUpdateKeyOps {
        s = append(s, "UPDATE_KEY_OPS")
    }
    return json.Marshal(s)
}

// UnmarshalJSON converts array of strings to QuorumGroupPermissions
func (x *QuorumGroupPermissions) UnmarshalJSON(data []byte) error {
    *x = 0
    var s []string
    if err := json.Unmarshal(data, &s); err != nil {
        return err
    }
    for _, v := range s {
        switch v {
        case "GET_SOBJECTS":
            *x = *x | QuorumGroupPermissionsGetSobjects
        case "ROTATE_SOBJECTS":
            *x = *x | QuorumGroupPermissionsRotateSobjects
        case "REVOKE_SOBJECTS":
            *x = *x | QuorumGroupPermissionsRevokeSobjects
        case "REVERT_SOBJECTS":
            *x = *x | QuorumGroupPermissionsRevertSobjects
        case "DELETE_KEY_MATERIAL":
            *x = *x | QuorumGroupPermissionsDeleteKeyMaterial
        case "DELETE_SOBJECTS":
            *x = *x | QuorumGroupPermissionsDeleteSobjects
        case "DESTROY_SOBJECTS":
            *x = *x | QuorumGroupPermissionsDestroySobjects
        case "MOVE_SOBJECTS":
            *x = *x | QuorumGroupPermissionsMoveSobjects
        case "CREATE_SOBJECTS":
            *x = *x | QuorumGroupPermissionsCreateSobjects
        case "UPDATE_SOBJECTS_PROFILE":
            *x = *x | QuorumGroupPermissionsUpdateSobjectsProfile
        case "UPDATE_SOBJECTS_ENABLED_STATE":
            *x = *x | QuorumGroupPermissionsUpdateSobjectsEnabledState
        case "UPDATE_SOBJECT_POLICIES":
            *x = *x | QuorumGroupPermissionsUpdateSobjectPolicies
        case "ACTIVATE_SOBJECTS":
            *x = *x | QuorumGroupPermissionsActivateSobjects
        case "UPDATE_KEY_OPS":
            *x = *x | QuorumGroupPermissionsUpdateKeyOps
        }
    }
    return nil
}

// An object for representing a scan of objects from a source HSM,
// DSM cluster, or cloud KMS.
type Scan struct {
    // The ID of the scan.
    ScanID UUID `json:"scan_id"`
    // Whether the scan is async or not.
    IsAsync bool `json:"is_async"`
    // The time the scan began.
    StartedAt Time `json:"started_at"`
    // The time the scan finished.
    FinishedAt *Time `json:"finished_at,omitempty"`
    // The "return status" of the scan.
    ScanResult *ScanResult `json:"scan_result,omitempty"`
    // Any warnings thrown during the scan.
    Warnings *[]ScanWarning `json:"warnings,omitempty"`
}

type ScanHmgRequest struct {
}

// The result of a scan.
type ScanResult struct {
    // Indicates that a scan completed successfully.
    Success *struct{}
    // Indicates that a scan has failed. The most recent error is included
    // (taken from the last retry).
    Failed *ScanResultFailed
}
// Indicates that a scan has failed. The most recent error is included
// (taken from the last retry).
type ScanResultFailed struct {
    Message string `json:"message"`
}
func (x ScanResult) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "ScanResult", 
                  []bool{ x.Success != nil,
                  x.Failed != nil });
                  err != nil {
        return nil, err
    }
    m := make(map[string]interface{})
    switch {
    case x.Success != nil:
        m["$type"] = "Success"
    case x.Failed != nil:
        b, err := json.Marshal(x.Failed)
        if err != nil {
            return nil, err
        }
        if err := json.Unmarshal(b, &m); err != nil {
            return nil, err
        }
        m["$type"] = "Failed"
    }
    return json.Marshal(m)
}
func (x *ScanResult) UnmarshalJSON(data []byte) error {
    x.Success = nil
    x.Failed = nil
    var h struct {
        Tag string `json:"$type"`
    }
    if err := json.Unmarshal(data, &h); err != nil {
        return errors.Errorf("not a valid ScanResult")
    }
    switch h.Tag {
    case "Success":
        x.Success = &struct{}{}
    case "Failed":
        var failed ScanResultFailed
        if err := json.Unmarshal(data, &failed); err != nil {
            return err
        }
        x.Failed = &failed
    default:
         return errors.Errorf("invalid tag value: %v", h.Tag)
    }
    return nil
}

// A warning "thrown" by a scan.
type ScanWarning struct {
    // The ID of the source key for which the warning applies to.
    SourceKeyID *UUID `json:"source_key_id,omitempty"`
    // The ID of the virtual key for which the warning applies to.
    VirtualKeyID *UUID `json:"virtual_key_id,omitempty"`
    // The warning message associated with the warning.
    Message string `json:"message"`
}

type WrappingKeyName struct {
    Null *struct{}
    Value *string
}
func (x WrappingKeyName) MarshalJSON() ([]byte, error) {
    if err := checkEnumPointers(
                  "WrappingKeyName", 
                  []bool{ x.Null != nil,
                  x.Value != nil });
                  err != nil {
        return nil, err
    }
    if x.Null != nil {
        return json.Marshal(x.Null)
    }
    if x.Value != nil {
        return json.Marshal(x.Value)
    }
    panic("unreachable")
}
func (x *WrappingKeyName) UnmarshalJSON(data []byte) error {
    x.Null = nil
    x.Value = nil
    var null struct{}
    if err := json.Unmarshal(data, &null); err == nil {
        x.Null = &null
        return nil
    }
    var value string
    if err := json.Unmarshal(data, &value); err == nil {
        x.Value = &value
        return nil
    }
    return errors.Errorf("not a valid WrappingKeyName")
}

// Scan external objects asynchronously.
//
// Scan external objects asynchronously and create corresponding
// virtual sobjects in the group as needed. If there is already a virtual
// sobject corresponding to a scanned object, no sobject is created.
// This is only supported for DSM-backed groups currently.
func (c *Client) AsyncScanHmg(ctx context.Context, group_id string) (*Scan, error) {
    u := "/sys/v1/groups/:group_id/hmg/scans"
    u = strings.NewReplacer(":group_id", group_id).Replace(u)
    var r Scan
    if err := c.fetch(ctx, http.MethodPost, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Check that the HMG configuration for a particular group is
// valid and reachable.
func (c *Client) CheckHmg(ctx context.Context, group_id string, body CheckHmgRequest) error {
    u := "/sys/v1/groups/:group_id/hmg/check"
    u = strings.NewReplacer(":group_id", group_id).Replace(u)
    if err := c.fetch(ctx, http.MethodPost, u, &body, nil); err != nil {
        return err
    }
    return nil
}

// Check that the HMG configuration provided is valid and reachable.
func (c *Client) CheckHmgConfig(ctx context.Context, body HmgConfig) error {
    u := "/sys/v1/groups/hmg/check"
    if err := c.fetch(ctx, http.MethodPost, u, &body, nil); err != nil {
        return err
    }
    return nil
}

// Create a new group with the specified properties.
func (c *Client) CreateGroup(ctx context.Context, body GroupRequest) (*Group, error) {
    u := "/sys/v1/groups"
    var r Group
    if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

func (c *Client) RequestApprovalToCreateGroup(
    ctx context.Context,    
body GroupRequest,
    description *string) (*ApprovalRequest, error) {
    u := "/sys/v1/groups"
    req := ApprovalRequestRequest{
        Method:      Some(http.MethodPost),
        Operation:   &u,
        Body:        &body,
        Description: description,
    }
    return c.CreateApprovalRequest(ctx, req)
}

// Delete the group.
func (c *Client) DeleteGroup(ctx context.Context, group_id string) error {
    u := "/sys/v1/groups/:group_id"
    u = strings.NewReplacer(":group_id", group_id).Replace(u)
    if err := c.fetch(ctx, http.MethodDelete, u, nil, nil); err != nil {
        return err
    }
    return nil
}

// Retrieve the scan status of an external group.
func (c *Client) GetAllHmgScans(ctx context.Context, group_id string) (*GetAllHmgScansResponse, error) {
    u := "/sys/v1/groups/:group_id/hmg/scans"
    u = strings.NewReplacer(":group_id", group_id).Replace(u)
    var r GetAllHmgScansResponse
    if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Given an GCP configuration, fetch a list of available
// GCP key rings which can be used to back a group.
func (c *Client) GetGcpKeyRings(ctx context.Context, body GcpKeyRingConfig) ([]string, error) {
    u := "/sys/v1/groups/hmg/gcp_key_rings"
    var r []string
    if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
        return nil, err
    }
    return r, nil
}

// Lookup a specific group.
func (c *Client) GetGroup(ctx context.Context, group_id string) (*Group, error) {
    u := "/sys/v1/groups/:group_id"
    u = strings.NewReplacer(":group_id", group_id).Replace(u)
    var r Group
    if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Query the status of a particular scan. Only the last five completed
// scans,as well as any in-progress scan, is queryable.
func (c *Client) GetScan(ctx context.Context, group_id string, scan_id string) (*Scan, error) {
    u := "/sys/v1/groups/:group_id/hmg/scans/:scan_id"
    u = strings.NewReplacer(":group_id", group_id, ":scan_id", scan_id).Replace(u)
    var r Scan
    if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Given an Azure configuration, fetch a list of available
// Azure key vaults which can be used to back a group.
func (c *Client) GetVaults(ctx context.Context, body HmgConfig) ([]KeyVault, error) {
    u := "/sys/v1/groups/hmg/azure_vaults"
    var r []KeyVault
    if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
        return nil, err
    }
    return r, nil
}

// Get all groups accessible to the requester.
func (c *Client) ListGroups(ctx context.Context, queryParameters *GetGroupsParams) (*ListGroupsResponse, error) {
    u := "/sys/v1/groups"
    if queryParameters != nil {
        q, err := encodeURLParams(queryParameters)
        if err != nil {
            return nil, err
        }
        u = fmt.Sprintf("%v?%v", u, q)
    }
    var r ListGroupsResponse
    if err := c.fetch(ctx, http.MethodGet, u, nil, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

// Scan external objects.
//
// Scan external objects synchronously and create corresponding
// virtual sobjects in the group as needed. If there is already a
// virtual sobject corresponding to a scanned object, no sobject
// is created.
func (c *Client) ScanHmg(ctx context.Context, group_id string, body ScanHmgRequest) ([]Sobject, error) {
    u := "/sys/v1/groups/:group_id/hmg/scan"
    u = strings.NewReplacer(":group_id", group_id).Replace(u)
    var r []Sobject
    if err := c.fetch(ctx, http.MethodPost, u, &body, &r); err != nil {
        return nil, err
    }
    return r, nil
}

// Change a group's properties.
func (c *Client) UpdateGroup(ctx context.Context, group_id string, body GroupRequest) (*Group, error) {
    u := "/sys/v1/groups/:group_id"
    u = strings.NewReplacer(":group_id", group_id).Replace(u)
    var r Group
    if err := c.fetch(ctx, http.MethodPatch, u, &body, &r); err != nil {
        return nil, err
    }
    return &r, nil
}

func (c *Client) RequestApprovalToUpdateGroup(
    ctx context.Context,    
group_id string,    
body GroupRequest,
    description *string) (*ApprovalRequest, error) {
    u := "/sys/v1/groups/:group_id"
    u = strings.NewReplacer(":group_id", group_id).Replace(u)
    req := ApprovalRequestRequest{
        Method:      Some(http.MethodPatch),
        Operation:   &u,
        Body:        &body,
        Description: description,
    }
    return c.CreateApprovalRequest(ctx, req)
}

