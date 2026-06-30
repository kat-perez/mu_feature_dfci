/**@file
SettingsManager.c

Implements the SettingAccess Provider

Copyright (C) Microsoft Corporation. All rights reserved.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SettingsManager.h"
#include <Library/PcdLib.h>
#include <Library/BaseLib.h>

//
// Setting IDs the dev-only PcdAcceptUnauthDeviceDisableSettings bypass
// applies to. String literals (not macros) so this list is independent
// of the Surface-side header. After DfciGroupLib alias resolution,
// any `Device.*` or `Dfci.*` user-facing name resolves to one of the
// IDs below before the permission check runs.
//
STATIC CONST CHAR8  *mDeviceDisableAllowlist[] = {
  // Group IDs accepted directly in a settings packet
  "Dfci.OnboardCameras.Enable",
  "Dfci.OnboardAudio.Enable",
  "Dfci.OnboardMic.Enable",
  "Dfci.OnboardRadios.Enable",
  "Dfci.AudioJackMic.Enable",
  "Dfci.WiFiOnly.Enable",
  "Dfci.WiFiAndBluetooth.Enable",
  "Dfci.Bluetooth.Enable",
  "Dfci.Nfc.Enable",
  "Dfci.WiredLan.Enable",
  "Dfci.MicroSDCard.Enable",
  "Dfci.UltraWideband.Enable",
  "Dfci.CAC.Enable",
  "Dfci.DockingUsbPort.Enable",
  "Dfci.BladeUsbPort.Enable",
  "Dfci.AccessoryRadioUsbPort.Enable",
  "Dfci.LteModemUsbPort.Enable",
  // Dfci4 group IDs (groups after DfciGroupLib expansion still flow back
  // through this function for each member, so they're listed too)
  "Dfci4.FrontCamera.Enable",
  "Dfci4.RearCamera.Enable",
  "Dfci4.IRCamera.Enable",
  "Dfci4.WFOVCamera.Enable",
  "Dfci4.Microphone.Enable",
  "Dfci4.Bluetooth.Enable",
  "Dfci4.WiFi.Enable",
  "Dfci4.Nfc.Enable",
  "Dfci4.WWANEnable",
  "Dfci4.UsbTypeAPort.Enable",
  "Dfci4.UsbTypeCPort.Enable",
  "Dfci4.Sdcard.Enable",
  // Leaf provider IDs that the group expansion resolves to. These are the
  // IDs `mSystemSettingAccessProtocol.Set` is actually invoked with after
  // SetSettingFromAscii walks the group members.
  "Device.FrontCamera.Enable",
  "Device.RearCamera.Enable",
  "Device.IRCamera.Enable",
  "Device.WfovCamera.Enable",
  "Device.AllCameras.Enable",
  "Device.OnboardAudio.Enable",
  "Device.OnboardMic.Enable",
  "Device.AudioJackMic.Enable",
  "Device.BlueTooth.Enable",
  "Device.WiFiOnly.Enable",
  "Device.WiFiAndBluetooth.Enable",
  "Device.Nfc.Enable",
  "Device.WiredLan.Enable",
  "Device.Sdcard.Enable",
  "Device.UltraWideband.Enable",
  "Device.SmartCard.Enable",
  "Device.LteModemUsbPort.Enable",
  "Device.WakeOnLan.Enable",
  "Device.WakeOnPower.Enable",
  "Surface.AccessoryRadioUsbPort.Enable",
  "Surface.BladeUsbPort.Enable",
  "Surface.DockingUsbPort.Enable",
  "Surface.UserUsbPort1.Enable",
  "Surface.UserUsbPort2.Enable",
  "Surface.UserUsbPort3.Enable",
  "Surface.UserUsbPort4.Enable",
  "Surface.UserUsbPort5.Enable",
  "Surface.UserUsbPort6.Enable",
  "Surface.UserUsbPort7.Enable",
  "Surface.UserUsbPort8.Enable",
  "Surface.UserUsbPort9.Enable",
  "Surface.UserUsbPort10.Enable",
  "Surface.UserUsbCPort1.Enable",
  "Surface.UserUsbCPort2.Enable",
  "Surface.UserUsbCPort3.Enable",
  "Surface.UserUsbCPort4.Enable",
  "Surface.UserUsbCPort5.Enable",
  "Surface.UserUsbCPort6.Enable",
  "Surface.UserUsbCPort7.Enable",
  "Surface.UserUsbCPort8.Enable",
  "Surface.UserUsbCPort9.Enable",
  "Surface.UserUsbCPort10.Enable",
};

STATIC
BOOLEAN
IsDeviceDisableAllowlistedId (
  IN DFCI_SETTING_ID_STRING  Id
  )
{
  UINTN  i;

  if (Id == NULL) {
    return FALSE;
  }

  for (i = 0; i < ARRAY_SIZE (mDeviceDisableAllowlist); i++) {
    if (AsciiStrCmp (Id, mDeviceDisableAllowlist[i]) == 0) {
      return TRUE;
    }
  }
  return FALSE;
}

/*
Set a single setting

@param[in] This:       Access Protocol
@param[in] Id:         Setting ID to set
@param[in] AuthToken:  A valid auth token to apply the setting using.  This auth token will be validated
to check permissions for changing the setting.
@param[in] Type:       Type that caller expects this setting to be.
@param[in] ValueSize   Size of the new value
@param[in] Value:      A pointer to a datatype defined by the Type for this setting.
@param[in,out] Flags:  Informational Flags passed to the SET and/or Returned as a result of the set

@retval EFI_SUCCESS if setting could be set.  Check flags for other info (reset required, etc)
@retval Error - Setting not set.

*/
EFI_STATUS
InternalSystemSettingAccessSet (
  IN  CONST DFCI_SETTING_ACCESS_PROTOCOL  *This,
  IN  DFCI_SETTING_ID_STRING              Id,
  IN  CONST DFCI_AUTH_TOKEN               *AuthToken,
  IN  DFCI_SETTING_TYPE                   Type,
  IN  UINTN                               ValueSize,
  IN  CONST VOID                          *Value,
  IN OUT DFCI_SETTING_FLAGS               *Flags
  )
{
  DFCI_SETTING_PROVIDER   *prov;
  DFCI_GROUP_LIST_ENTRY   *Group;
  DFCI_MEMBER_LIST_ENTRY  *Member;
  LIST_ENTRY              *Link;
  EFI_STATUS              ReturnStatus;
  EFI_STATUS              Status;
  BOOLEAN                 AuthStatus = FALSE;
  STATIC BOOLEAN          SetRecurse = FALSE;

  // Check parameters
  if ((This == NULL) || (Value == NULL) || (AuthToken == NULL) || (Flags == NULL) | (Id == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  // Get provider and verify type
  prov = FindProviderById (Id);

  if (prov == NULL) {
    if (SetRecurse) {
      DEBUG ((DEBUG_ERROR, "%a: Unexpected recursion.\n", __FUNCTION__));
      ASSERT (!SetRecurse);
      return EFI_UNSUPPORTED;
    }

    // May be group setting
    Group = FindGroup (Id);
    if (Group == NULL) {
      DEBUG ((DEBUG_ERROR, "%a - Requested ID (%a) not found.\n", __FUNCTION__, Id));
      return EFI_NOT_FOUND;
    }

    ReturnStatus = EFI_SUCCESS;
    EFI_LIST_FOR_EACH (Link, &Group->MemberHead) {
      Member     = MEMBER_LIST_ENTRY_FROM_MEMBER_LINK (Link);
      SetRecurse = TRUE;
      Status     = InternalSystemSettingAccessSet (
                     This,
                     Member->Id,
                     AuthToken,
                     Type,
                     ValueSize,
                     Value,
                     Flags
                     );
      SetRecurse = FALSE;
      if (EFI_ERROR (Status)) {
        ReturnStatus = Status;
      }
    }

    return ReturnStatus;
  }

  // Dev-only short-circuit: bypass the entire write-permission check
  // (including any error or denial from HasWritePermissions) for
  // device-disable setting IDs when the PCD is TRUE.
  if (FeaturePcdGet (PcdAcceptUnauthDeviceDisableSettings) && IsDeviceDisableAllowlistedId (Id)) {
    DEBUG ((DEBUG_WARN, "%a - PcdAcceptUnauthDeviceDisableSettings bypass: allowing %a\n", __FUNCTION__, Id));
  } else {
    // Check Auth for the setting Id.
    Status = HasWritePermissions (Id, AuthToken, &AuthStatus);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a - HasWritePermissions returned an error %r\n", __FUNCTION__, Status));
      return Status;
    }

    // if no write access to group ID return access denied
    if (!AuthStatus) {
      DEBUG ((DEBUG_INFO, "%a - No Permission to write setting %a\n", __FUNCTION__, Id));
      return EFI_ACCESS_DENIED;
    }
  }

  if (Type != prov->Type) {
    DEBUG ((DEBUG_ERROR, "Caller supplied type (0x%X) and provider type (0x%X) don't match\n", Type, prov->Type));
    ASSERT (Type == prov->Type);
    return EFI_INVALID_PARAMETER;
  }

  // Set the current setting to the new value.
  Status = prov->SetSettingValue (prov, ValueSize, Value, Flags);
  if (EFI_ERROR (Status)) {
    if (Status == EFI_BAD_BUFFER_SIZE) {
      DEBUG ((DEBUG_ERROR, "%a: Bad size requested for setting provider!\n", __FUNCTION__));
      ASSERT_EFI_ERROR (Status);
    }

    DEBUG ((DEBUG_ERROR, "Failed to Set Settings\n"));
    return Status;
  }

  if ((*Flags & DFCI_SETTING_FLAGS_OUT_ALREADY_SET) == 0) {
    // Status was good and flags don't indicate that value was already set.

    Status = DfciSettingChangedNotification (
               Id,
               AuthToken,
               Type,
               ValueSize,
               Value,
               *Flags
               );

    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "DfciSettingChangedNotification returned error code=%r\n", Status));
    }
  }

  return Status;
}

/*
Set a single setting

@param[in] This:       Access Protocol
@param[in] Id:         Setting ID to set
@param[in] AuthToken:  A valid auth token to apply the setting using.  This auth token will be validated
to check permissions for changing the setting.
@param[in] Type:       Type that caller expects this setting to be.
@param[in] ValueSize   Size of the new value
@param[in] Value:      A pointer to a datatype defined by the Type for this setting.
@param[in,out] Flags:  Informational Flags passed to the SET and/or Returned as a result of the set

@retval EFI_SUCCESS if setting could be set.  Check flags for other info (reset required, etc)
@retval Error - Setting not set.

*/
EFI_STATUS
EFIAPI
SystemSettingAccessSet (
  IN  CONST DFCI_SETTING_ACCESS_PROTOCOL  *This,
  IN  DFCI_SETTING_ID_STRING              Id,
  IN  CONST DFCI_AUTH_TOKEN               *AuthToken,
  IN  DFCI_SETTING_TYPE                   Type,
  IN  UINTN                               ValueSize,
  IN  CONST VOID                          *Value,
  IN OUT DFCI_SETTING_FLAGS               *Flags
  )
{
  return InternalSystemSettingAccessSet (
           This,
           Id,
           AuthToken,
           Type,
           ValueSize,
           Value,
           Flags
           );
}

/*
Get a single setting

@param[in] This:        Access Protocol
@param[in] Id:          Setting ID to Get
@param[in] AuthToken:   An optional auth token* to use to check permission of setting.  This auth token will be validated
to check permissions for changing the setting which will be reported in flags if valid.
@param[in] Type:        Type that caller expects this setting to be.
@param[in,out] ValueSize On input, size of the buffer provided, on output size of buffer needed
@param[out] Value:      A pointer to a datatype defined by the Type for this setting.
@param[IN OUT] Flags    Optional Informational flags passed back from the Get operation.  If the Auth Token is valid write access will be set in
flags for the given auth.


@retval EFI_SUCCESS if setting could be set.  Check flags for other info (reset required, etc)
@retval Error - couldn't get setting.

*/
EFI_STATUS
InternalSystemSettingAccessGet (
  IN  CONST DFCI_SETTING_ACCESS_PROTOCOL *This,
  IN  DFCI_SETTING_ID_STRING Id,
  IN  CONST DFCI_AUTH_TOKEN *AuthToken, OPTIONAL
  IN  DFCI_SETTING_TYPE                   Type,
  IN OUT UINTN                           *ValueSize,
  OUT VOID                               *Value,
  IN OUT DFCI_SETTING_FLAGS              *Flags OPTIONAL
  )
{
  DFCI_SETTING_PROVIDER   *prov = NULL;
  DFCI_GROUP_LIST_ENTRY   *Group;
  DFCI_MEMBER_LIST_ENTRY  *Member;
  LIST_ENTRY              *Link;
  EFI_STATUS              ReturnStatus;
  EFI_STATUS              Status     = EFI_SUCCESS;
  STATIC BOOLEAN          GetRecurse = FALSE;
  UINT8                   LocalValue;
  UINT8                   MasterValue;
  UINTN                   LocalSize;

  // Check parameters
  if ((This == NULL) || (Value == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  // Get provider and verify type
  prov = FindProviderById (Id);

  if (prov == NULL) {
    if (GetRecurse) {
      DEBUG ((DEBUG_ERROR, "%a: Unexpected recursion.\n", __FUNCTION__));
      ASSERT (!GetRecurse);
      return EFI_UNSUPPORTED;
    }

    // May be group setting
    Group = FindGroup (Id);
    if (Group == NULL) {
      DEBUG ((DEBUG_ERROR, "%a - Requested ID (%a) not found.\n", __FUNCTION__, Id));
      return EFI_NOT_FOUND;
    }

    if (*ValueSize < 1) {
      *ValueSize = sizeof (UINT8);
      return EFI_BUFFER_TOO_SMALL;
    }

    ReturnStatus = EFI_SUCCESS;
    MasterValue  = ENABLE_INCONSISTENT; // Some value not ENABLE_TRUE or ENABLE_FALSE
    EFI_LIST_FOR_EACH (Link, &Group->MemberHead) {
      Member     = MEMBER_LIST_ENTRY_FROM_MEMBER_LINK (Link);
      LocalSize  = sizeof (LocalValue);
      GetRecurse = TRUE;
      Status     = InternalSystemSettingAccessGet (
                     This,
                     Member->Id,
                     AuthToken,
                     Type,
                     &LocalSize,
                     &LocalValue,
                     Flags
                     );
      GetRecurse = FALSE;
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "%a: Unexpected return from AccessGet. Code=%r\n", __FUNCTION__, Status));
        ReturnStatus = Status;
        continue;
      }

      DEBUG ((DEBUG_INFO, "Value of %a is %x\n", Member->Id, (UINTN)LocalValue));

      if (ENABLE_INCONSISTENT == MasterValue) {
        MasterValue = LocalValue;
      } else {
        if (MasterValue != LocalValue) {
          MasterValue = ENABLE_INCONSISTENT;
          break;
        }
      }
    }

    // On Success, set *Value and *ValueSize
    // On Buffer Too Small, only set *ValueSize
    // All other errors do not alter *Value or *ValueSize
    switch (ReturnStatus) {
      case EFI_SUCCESS:
        *((UINT8 *)Value) = MasterValue;
      case EFI_BUFFER_TOO_SMALL:
        *ValueSize = sizeof (UINT8);
        break;
    }

    return ReturnStatus;
  }

  if (Type != prov->Type) {
    DEBUG ((DEBUG_ERROR, "Caller supplied type (0x%X) and provider type (0x%X) don't match\n", Type, prov->Type));
    ASSERT (Type == prov->Type);
    return EFI_INVALID_PARAMETER;
  }

  if (Flags != NULL) {
    // return the provider flags
    *Flags = prov->Flags;
  }

  //
  // Go check the permission
  //
  if ((AuthToken != NULL) && (Flags != NULL)) {
    BOOLEAN  AuthStatus = FALSE;
    Status = HasWritePermissions (Id, AuthToken, &AuthStatus);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_INFO, "%a - Failed to get Write Permission for Id %a Status %r\n", __FUNCTION__, Id, Status));
      AuthStatus = FALSE;
    }

    if (AuthStatus) {
      *Flags |= DFCI_SETTING_FLAGS_OUT_WRITE_ACCESS;  // add write access if AuthStatus is TRUE
    }
  }

  return prov->GetSettingValue (prov, ValueSize, Value);
}

/*
Get a single setting

@param[in] This:        Access Protocol
@param[in] Id:          Setting ID to Get
@param[in] AuthToken:   An optional auth token* to use to check permission of setting.  This auth token will be validated
to check permissions for changing the setting which will be reported in flags if valid.
@param[in] Type:        Type that caller expects this setting to be.
@param[in,out] ValueSize On input, size of the buffer provided, on output size of buffer needed
@param[out] Value:      A pointer to a datatype defined by the Type for this setting.
@param[IN OUT] Flags    Optional Informational flags passed back from the Get operation.  If the Auth Token is valid write access will be set in
flags for the given auth.

@retval EFI_SUCCESS if setting could be set.  Check flags for other info (reset required, etc)
@retval Error - couldn't get setting.

*/
EFI_STATUS
EFIAPI
SystemSettingAccessGet (
  IN  CONST DFCI_SETTING_ACCESS_PROTOCOL *This,
  IN  DFCI_SETTING_ID_STRING Id,
  IN  CONST DFCI_AUTH_TOKEN *AuthToken, OPTIONAL
  IN  DFCI_SETTING_TYPE                   Type,
  IN OUT UINTN                           *ValueSize,
  OUT VOID                               *Value,
  IN OUT DFCI_SETTING_FLAGS              *Flags OPTIONAL
  )
{
  return InternalSystemSettingAccessGet (
           This,
           Id,
           AuthToken,
           Type,
           ValueSize,
           Value,
           Flags
           );
}

/*
Reset Settings Access

This will clear all internal Settings Access Data
This will reset all settings that have DFCI_SETTING_FLAGS_NO_PREBOOT_UI set

@param[in] This:        Access Protocol
@param[in] AuthToken:   An  auth token to authorize the operation.  Only an auth token with recovery and/or Owner Auth Key permissions
can perform a reset.

@retval EFI_SUCCESS   - Settings access clear completed
@retval Error - failed

*/
EFI_STATUS
EFIAPI
SystemSettingsAccessReset (
  IN  CONST DFCI_SETTING_ACCESS_PROTOCOL  *This,
  IN  CONST DFCI_AUTH_TOKEN               *AuthToken
  )
{
  BOOLEAN     CanUnenroll = FALSE;
  EFI_STATUS  Status;

  // Check parameters
  if ((This == NULL) || (AuthToken == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = HasUnenrollPermission (AuthToken, &CanUnenroll);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to get recovery permission. Status = %r\n", __FUNCTION__, Status));
    return Status;
  }

  if (!CanUnenroll) {
    DEBUG ((DEBUG_INFO, "%a - Auth Token doesn't have permission to reset settings\n", __FUNCTION__));
    return EFI_ACCESS_DENIED;
  }

  Status = ResetAllProvidersToDefaultsWithMatchingFlags (DFCI_SETTING_FLAGS_NO_PREBOOT_UI);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to reset all settings to defaults. Status = %r\n", __FUNCTION__, Status));
    ASSERT_EFI_ERROR (Status); // if cleanup fails on production system nothing we can do...keep going
  }

  Status = SMID_ResetInFlash ();  // clear the internal storage
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to Reset Settings Internal Data Status = %r\n", __FUNCTION__, Status));
    ASSERT_EFI_ERROR (Status);  // if cleanup fails on production system nothing we can do...keep going
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SystemSettingPermissionGetPermission (
  IN  CONST DFCI_SETTING_PERMISSIONS_PROTOCOL  *This,
  IN  DFCI_SETTING_ID_STRING                   Id,
  OUT DFCI_PERMISSION_MASK                     *PermissionMask
  )
{
  if ((This == NULL) || (PermissionMask == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  return QueryPermission (Id, PermissionMask);
}

EFI_STATUS
EFIAPI
SystemSettingPermissionResetPermission (
  IN  CONST DFCI_SETTING_PERMISSIONS_PROTOCOL  *This,
  IN  CONST DFCI_AUTH_TOKEN                    *AuthToken
  )
{
  EFI_STATUS  Status;

  if ((This == NULL) || (AuthToken == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = ResetPermissionsToDefault (AuthToken);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to Reset Permissions Status = %r\n", __FUNCTION__, Status));
  }

  return Status;
}

EFI_STATUS
EFIAPI
SystemSettingPermissionIdentityChange (
  IN  CONST DFCI_SETTING_PERMISSIONS_PROTOCOL  *This,
  IN  CONST DFCI_AUTH_TOKEN                    *AuthToken,
  IN        DFCI_IDENTITY_ID                   CertIdentity,
  IN        IDENTITY_CHANGE_TYPE               ChangeType
  )
{
  EFI_STATUS  Status;

  if ((This == NULL) || (AuthToken == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = IdentityChange (AuthToken, CertIdentity, ChangeType);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to Reset Permissions. Status = %r\n", __FUNCTION__, Status));
  }

  return Status;
}
