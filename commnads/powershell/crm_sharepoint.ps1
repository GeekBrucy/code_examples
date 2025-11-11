<#
  This script collects everything we explored about:
  - Reading OptionSet metadata
  - Mapping SharePoint string values to CRM integer values
  - Creating or updating CRM records
  - Handling Picklist / MultiSelect / Lookup / Boolean / Money field types

  💡 Tip:
  You can dot-source this file in other scripts:
      . "C:\Scripts\CrmPicklistHelper.ps1"
#>

# ======================
# 1️⃣ Load metadata
# ======================

# Retrieve all metadata for the Lead entity.
# This gives you access to all attributes and their types.
$meta = Get-CrmEntityMetadata -EntityLogicalName lead

# To inspect one particular field (replace 'new_leadtype' with your schema name):
$attr = $meta.Attributes | Where-Object { $_.LogicalName -eq 'new_leadtype' }

# Check what kind of field it is (Picklist, Lookup, Boolean, etc.)
$attr | Select LogicalName, AttributeTypeName, OptionSetName, Targets

# ======================
# 2️⃣ Get OptionSet options (label-value pairs)
# ======================

# This command works for Picklists and Global OptionSets.
# If the field is a global OptionSet, you'll need OptionSetName from the previous step.
$meta = Get-CrmEntityAttributeMeta -EntityLogicalName lead -FieldLogicalName new_leadtype

# Display the label/value pairs in a clean format
$meta.OptionSetOptions | ForEach-Object {
  [PSCustomObject]@{
    Label = $_.Label.UserLocalizedLabel.Label
    Value = $_.Value
  }
}

# Export to CSV if you want to keep a reference
$meta.OptionSetOptions | ForEach-Object {
  [PSCustomObject]@{
    Label = $_.Label.UserLocalizedLabel.Label
    Value = $_.Value
  }
} | Export-Csv -Path "C:\LeadTypeOptions.csv" -NoTypeInformation


# ======================
# 3️⃣ SharePoint -> CRM mapping example
# ======================

# Define a static mapping (SharePoint string → CRM integer)
$leadTypeMap = @{
  'Cold Lead' = 100000001
  'Warm Lead' = 100000002
  'Hot Lead'  = 100000003
}

# Example SharePoint field value
$sharePointValue = 'Warm Lead'

# Always trim the SharePoint value (it may contain trailing spaces)
$sharePointValue = $sharePointValue.Trim()

# Check if the key exists in the mapping before using it
if (-not $leadTypeMap.ContainsKey($sharePointValue)) {
  Write-Warning "Unrecognized SharePoint value: $sharePointValue"
  return
}

# Retrieve and cast to integer
$crmValue = [int]$leadTypeMap[$sharePointValue]

# Wrap it in an OptionSetValue (⚠️ mandatory for Picklists)
$leadTypeValue = New-Object Microsoft.Xrm.Sdk.OptionSetValue($crmValue)

# ======================
# 4️⃣ Create or update CRM record
# ======================

# Creating a new record
New-CrmRecord -EntityLogicalName lead -Fields @{
  subject      = "Lead from SharePoint"
  firstname    = "Bruce"
  lastname     = "Zhou"
  new_leadtype = $leadTypeValue
}

# Updating an existing record
# (Note: replace $leadId with the actual record ID GUID)
# Set-CrmRecord -EntityLogicalName lead -Id $leadId -Fields @{
#     new_leadtype = New-Object Microsoft.Xrm.Sdk.OptionSetValue(100000002)
# }


# ======================
# 5️⃣ Other field type helpers
# ======================

# Lookup field → use EntityReference
# Example: linking to Account
# $accountRef = New-CrmEntityReference -EntityLogicalName account -Id $accountGuid

# Multi-select Picklist → use OptionSetValueCollection
# $vals = New-Object Microsoft.Xrm.Sdk.OptionSetValueCollection
# @(100000001,100000002) | ForEach-Object { [void]$vals.Add((New-Object Microsoft.Xrm.Sdk.OptionSetValue($_))) }

# Boolean field → pass as $true or $false
# Currency field → New-Object Microsoft.Xrm.Sdk.Money(99.99)


# ======================
# 6️⃣ Diagnostics / metadata checks
# ======================

# Get the attribute metadata again to confirm the type
Get-CrmEntityAttributeMetadata -EntityLogicalName lead -FieldLogicalName new_leadtype |
Select-Object LogicalName, AttributeTypeName, AttributeType

# Verify if your task scheduler or pipeline can manually trigger the script
# Run manually in Windows Task Scheduler:
#     Start-ScheduledTask -TaskName "YourTaskName"
# or via cmd:
#     schtasks /run /tn "YourTaskName"

# Check scheduled task run results (optional)
# Get-ScheduledTask -TaskName "YourTaskName" | Get-ScheduledTaskInfo


# ======================
# 7️⃣ Utility helper functions (optional)
# ======================

function Convert-ToOptionSetValue {
  param(
    [Parameter(Mandatory)]
    [int]$Value
  )
  return (New-Object Microsoft.Xrm.Sdk.OptionSetValue($Value))
}

function Get-CrmPicklistOptions {
  param(
    [Parameter(Mandatory)]
    [string]$EntityLogicalName,
    [Parameter(Mandatory)]
    [string]$FieldLogicalName
  )
  $meta = Get-CrmEntityAttributeMeta -EntityLogicalName $EntityLogicalName -FieldLogicalName $FieldLogicalName
  return $meta.OptionSetOptions | ForEach-Object {
    [PSCustomObject]@{
      Label = $_.Label.UserLocalizedLabel.Label
      Value = $_.Value
    }
  }
}

# Example usage:
# Get-CrmPicklistOptions -EntityLogicalName lead -FieldLogicalName new_leadtype
# Convert-ToOptionSetValue 100000001

# ======================
# END
# ======================

Write-Host "`n✅ CRM Picklist Helper Loaded Successfully! Use Get-CrmPicklistOptions or Convert-ToOptionSetValue as needed."