// eossdk_proxy.cpp  --  EOS SDK anti-cheat stub proxy
//
// All EOS_AntiCheat* functions return 0 (EOS_Success) immediately.
// All other 629 functions are forwarded to EOSSDK_real.dll via PE exports.
//
// Deploy:
//   1. Rename EOSSDK-Win64-Shipping.dll -> EOSSDK_real.dll  (same folder)
//   2. Copy   EOSSDK-Win64-Shipping.dll (this proxy) into the same folder
//
// Build:
//   cl /LD /O2 /nologo eossdk_proxy.cpp /link /MACHINE:X64
//
// Revert:
//   Delete EOSSDK-Win64-Shipping.dll, rename EOSSDK_real.dll back.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// ---- Forwarded exports -> EOSSDK_real.dll -------------------------
#pragma comment(linker, "/EXPORT:EOS_Achievements_AddNotifyAchievementsUnlocked=EOSSDK_real.EOS_Achievements_AddNotifyAchievementsUnlocked")
#pragma comment(linker, "/EXPORT:EOS_Achievements_AddNotifyAchievementsUnlockedV2=EOSSDK_real.EOS_Achievements_AddNotifyAchievementsUnlockedV2")
#pragma comment(linker, "/EXPORT:EOS_Achievements_CopyAchievementDefinitionByAchievementId=EOSSDK_real.EOS_Achievements_CopyAchievementDefinitionByAchievementId")
#pragma comment(linker, "/EXPORT:EOS_Achievements_CopyAchievementDefinitionByIndex=EOSSDK_real.EOS_Achievements_CopyAchievementDefinitionByIndex")
#pragma comment(linker, "/EXPORT:EOS_Achievements_CopyAchievementDefinitionV2ByAchievementId=EOSSDK_real.EOS_Achievements_CopyAchievementDefinitionV2ByAchievementId")
#pragma comment(linker, "/EXPORT:EOS_Achievements_CopyAchievementDefinitionV2ByIndex=EOSSDK_real.EOS_Achievements_CopyAchievementDefinitionV2ByIndex")
#pragma comment(linker, "/EXPORT:EOS_Achievements_CopyPlayerAchievementByAchievementId=EOSSDK_real.EOS_Achievements_CopyPlayerAchievementByAchievementId")
#pragma comment(linker, "/EXPORT:EOS_Achievements_CopyPlayerAchievementByIndex=EOSSDK_real.EOS_Achievements_CopyPlayerAchievementByIndex")
#pragma comment(linker, "/EXPORT:EOS_Achievements_CopyUnlockedAchievementByAchievementId=EOSSDK_real.EOS_Achievements_CopyUnlockedAchievementByAchievementId")
#pragma comment(linker, "/EXPORT:EOS_Achievements_CopyUnlockedAchievementByIndex=EOSSDK_real.EOS_Achievements_CopyUnlockedAchievementByIndex")
#pragma comment(linker, "/EXPORT:EOS_Achievements_Definition_Release=EOSSDK_real.EOS_Achievements_Definition_Release")
#pragma comment(linker, "/EXPORT:EOS_Achievements_DefinitionV2_Release=EOSSDK_real.EOS_Achievements_DefinitionV2_Release")
#pragma comment(linker, "/EXPORT:EOS_Achievements_GetAchievementDefinitionCount=EOSSDK_real.EOS_Achievements_GetAchievementDefinitionCount")
#pragma comment(linker, "/EXPORT:EOS_Achievements_GetPlayerAchievementCount=EOSSDK_real.EOS_Achievements_GetPlayerAchievementCount")
#pragma comment(linker, "/EXPORT:EOS_Achievements_GetUnlockedAchievementCount=EOSSDK_real.EOS_Achievements_GetUnlockedAchievementCount")
#pragma comment(linker, "/EXPORT:EOS_Achievements_PlayerAchievement_Release=EOSSDK_real.EOS_Achievements_PlayerAchievement_Release")
#pragma comment(linker, "/EXPORT:EOS_Achievements_QueryDefinitions=EOSSDK_real.EOS_Achievements_QueryDefinitions")
#pragma comment(linker, "/EXPORT:EOS_Achievements_QueryPlayerAchievements=EOSSDK_real.EOS_Achievements_QueryPlayerAchievements")
#pragma comment(linker, "/EXPORT:EOS_Achievements_RemoveNotifyAchievementsUnlocked=EOSSDK_real.EOS_Achievements_RemoveNotifyAchievementsUnlocked")
#pragma comment(linker, "/EXPORT:EOS_Achievements_UnlockAchievements=EOSSDK_real.EOS_Achievements_UnlockAchievements")
#pragma comment(linker, "/EXPORT:EOS_Achievements_UnlockedAchievement_Release=EOSSDK_real.EOS_Achievements_UnlockedAchievement_Release")
#pragma comment(linker, "/EXPORT:EOS_ActiveSession_CopyInfo=EOSSDK_real.EOS_ActiveSession_CopyInfo")
#pragma comment(linker, "/EXPORT:EOS_ActiveSession_GetRegisteredPlayerByIndex=EOSSDK_real.EOS_ActiveSession_GetRegisteredPlayerByIndex")
#pragma comment(linker, "/EXPORT:EOS_ActiveSession_GetRegisteredPlayerCount=EOSSDK_real.EOS_ActiveSession_GetRegisteredPlayerCount")
#pragma comment(linker, "/EXPORT:EOS_ActiveSession_Info_Release=EOSSDK_real.EOS_ActiveSession_Info_Release")
#pragma comment(linker, "/EXPORT:EOS_ActiveSession_Release=EOSSDK_real.EOS_ActiveSession_Release")
#pragma comment(linker, "/EXPORT:EOS_Audio_CreateNewInputStream=EOSSDK_real.EOS_Audio_CreateNewInputStream")
#pragma comment(linker, "/EXPORT:EOS_Audio_CreateNewOutputStream=EOSSDK_real.EOS_Audio_CreateNewOutputStream")
#pragma comment(linker, "/EXPORT:EOS_Audio_DestroyInputStream=EOSSDK_real.EOS_Audio_DestroyInputStream")
#pragma comment(linker, "/EXPORT:EOS_Audio_DestroyOutputStream=EOSSDK_real.EOS_Audio_DestroyOutputStream")
#pragma comment(linker, "/EXPORT:EOS_Audio_EnableCommunicationsModeOutputDevices=EOSSDK_real.EOS_Audio_EnableCommunicationsModeOutputDevices")
#pragma comment(linker, "/EXPORT:EOS_Audio_GetInputDeviceInfo=EOSSDK_real.EOS_Audio_GetInputDeviceInfo")
#pragma comment(linker, "/EXPORT:EOS_Audio_GetInputStreamInfo=EOSSDK_real.EOS_Audio_GetInputStreamInfo")
#pragma comment(linker, "/EXPORT:EOS_Audio_GetOutputDeviceInfo=EOSSDK_real.EOS_Audio_GetOutputDeviceInfo")
#pragma comment(linker, "/EXPORT:EOS_Audio_GetOutputStreamInfo=EOSSDK_real.EOS_Audio_GetOutputStreamInfo")
#pragma comment(linker, "/EXPORT:EOS_Audio_IsInputStreamDeviceDisconnected=EOSSDK_real.EOS_Audio_IsInputStreamDeviceDisconnected")
#pragma comment(linker, "/EXPORT:EOS_Audio_IsInputStreamSilent=EOSSDK_real.EOS_Audio_IsInputStreamSilent")
#pragma comment(linker, "/EXPORT:EOS_Audio_QueryInputDevices=EOSSDK_real.EOS_Audio_QueryInputDevices")
#pragma comment(linker, "/EXPORT:EOS_Audio_QueryOutputDevices=EOSSDK_real.EOS_Audio_QueryOutputDevices")
#pragma comment(linker, "/EXPORT:EOS_Audio_RegisterUser=EOSSDK_real.EOS_Audio_RegisterUser")
#pragma comment(linker, "/EXPORT:EOS_Audio_RemoveNotifyDevicesChanged=EOSSDK_real.EOS_Audio_RemoveNotifyDevicesChanged")
#pragma comment(linker, "/EXPORT:EOS_Audio_SetFeatureEnabledForInputStream=EOSSDK_real.EOS_Audio_SetFeatureEnabledForInputStream")
#pragma comment(linker, "/EXPORT:EOS_Audio_SetNotifyDevicesChanged=EOSSDK_real.EOS_Audio_SetNotifyDevicesChanged")
#pragma comment(linker, "/EXPORT:EOS_Audio_StartInputStream=EOSSDK_real.EOS_Audio_StartInputStream")
#pragma comment(linker, "/EXPORT:EOS_Audio_StartOutputStream=EOSSDK_real.EOS_Audio_StartOutputStream")
#pragma comment(linker, "/EXPORT:EOS_Audio_StopInputStream=EOSSDK_real.EOS_Audio_StopInputStream")
#pragma comment(linker, "/EXPORT:EOS_Audio_StopOutputStream=EOSSDK_real.EOS_Audio_StopOutputStream")
#pragma comment(linker, "/EXPORT:EOS_Audio_UnregisterUser=EOSSDK_real.EOS_Audio_UnregisterUser")
#pragma comment(linker, "/EXPORT:EOS_Auth_AddNotifyLoginStatusChanged=EOSSDK_real.EOS_Auth_AddNotifyLoginStatusChanged")
#pragma comment(linker, "/EXPORT:EOS_Auth_CopyIdToken=EOSSDK_real.EOS_Auth_CopyIdToken")
#pragma comment(linker, "/EXPORT:EOS_Auth_CopyUserAuthToken=EOSSDK_real.EOS_Auth_CopyUserAuthToken")
#pragma comment(linker, "/EXPORT:EOS_Auth_DeletePersistentAuth=EOSSDK_real.EOS_Auth_DeletePersistentAuth")
#pragma comment(linker, "/EXPORT:EOS_Auth_GetLoggedInAccountByIndex=EOSSDK_real.EOS_Auth_GetLoggedInAccountByIndex")
#pragma comment(linker, "/EXPORT:EOS_Auth_GetLoggedInAccountsCount=EOSSDK_real.EOS_Auth_GetLoggedInAccountsCount")
#pragma comment(linker, "/EXPORT:EOS_Auth_GetLoginStatus=EOSSDK_real.EOS_Auth_GetLoginStatus")
#pragma comment(linker, "/EXPORT:EOS_Auth_GetMergedAccountByIndex=EOSSDK_real.EOS_Auth_GetMergedAccountByIndex")
#pragma comment(linker, "/EXPORT:EOS_Auth_GetMergedAccountsCount=EOSSDK_real.EOS_Auth_GetMergedAccountsCount")
#pragma comment(linker, "/EXPORT:EOS_Auth_GetSelectedAccountId=EOSSDK_real.EOS_Auth_GetSelectedAccountId")
#pragma comment(linker, "/EXPORT:EOS_Auth_IdToken_Release=EOSSDK_real.EOS_Auth_IdToken_Release")
#pragma comment(linker, "/EXPORT:EOS_Auth_LinkAccount=EOSSDK_real.EOS_Auth_LinkAccount")
#pragma comment(linker, "/EXPORT:EOS_Auth_Login=EOSSDK_real.EOS_Auth_Login")
#pragma comment(linker, "/EXPORT:EOS_Auth_Logout=EOSSDK_real.EOS_Auth_Logout")
#pragma comment(linker, "/EXPORT:EOS_Auth_QueryIdToken=EOSSDK_real.EOS_Auth_QueryIdToken")
#pragma comment(linker, "/EXPORT:EOS_Auth_RemoveNotifyLoginStatusChanged=EOSSDK_real.EOS_Auth_RemoveNotifyLoginStatusChanged")
#pragma comment(linker, "/EXPORT:EOS_Auth_Token_Release=EOSSDK_real.EOS_Auth_Token_Release")
#pragma comment(linker, "/EXPORT:EOS_Auth_VerifyIdToken=EOSSDK_real.EOS_Auth_VerifyIdToken")
#pragma comment(linker, "/EXPORT:EOS_Auth_VerifyUserAuth=EOSSDK_real.EOS_Auth_VerifyUserAuth")
#pragma comment(linker, "/EXPORT:EOS_BeginScopeEvent=EOSSDK_real.EOS_BeginScopeEvent")
#pragma comment(linker, "/EXPORT:EOS_BroadcastAudio_CreateNewInputStream=EOSSDK_real.EOS_BroadcastAudio_CreateNewInputStream")
#pragma comment(linker, "/EXPORT:EOS_BroadcastAudio_CreateNewOutputStream=EOSSDK_real.EOS_BroadcastAudio_CreateNewOutputStream")
#pragma comment(linker, "/EXPORT:EOS_BroadcastAudio_DestroyInputStream=EOSSDK_real.EOS_BroadcastAudio_DestroyInputStream")
#pragma comment(linker, "/EXPORT:EOS_BroadcastAudio_DestroyOutputStream=EOSSDK_real.EOS_BroadcastAudio_DestroyOutputStream")
#pragma comment(linker, "/EXPORT:EOS_BroadcastAudio_GetCurrentGainLevel=EOSSDK_real.EOS_BroadcastAudio_GetCurrentGainLevel")
#pragma comment(linker, "/EXPORT:EOS_BroadcastAudio_GetCurrentMicAmplitude=EOSSDK_real.EOS_BroadcastAudio_GetCurrentMicAmplitude")
#pragma comment(linker, "/EXPORT:EOS_BroadcastAudio_GetInputStreamInfo=EOSSDK_real.EOS_BroadcastAudio_GetInputStreamInfo")
#pragma comment(linker, "/EXPORT:EOS_BroadcastAudio_GetOutputStreamInfo=EOSSDK_real.EOS_BroadcastAudio_GetOutputStreamInfo")
#pragma comment(linker, "/EXPORT:EOS_BroadcastAudio_PushPacketToOutputStream=EOSSDK_real.EOS_BroadcastAudio_PushPacketToOutputStream")
#pragma comment(linker, "/EXPORT:EOS_BroadcastAudio_SetEncoderSettings=EOSSDK_real.EOS_BroadcastAudio_SetEncoderSettings")
#pragma comment(linker, "/EXPORT:EOS_BroadcastAudio_SetMicProcessingSettings=EOSSDK_real.EOS_BroadcastAudio_SetMicProcessingSettings")
#pragma comment(linker, "/EXPORT:EOS_BroadcastAudio_StartInputStream=EOSSDK_real.EOS_BroadcastAudio_StartInputStream")
#pragma comment(linker, "/EXPORT:EOS_BroadcastAudio_StartOutputStream=EOSSDK_real.EOS_BroadcastAudio_StartOutputStream")
#pragma comment(linker, "/EXPORT:EOS_BroadcastAudio_StopInputStream=EOSSDK_real.EOS_BroadcastAudio_StopInputStream")
#pragma comment(linker, "/EXPORT:EOS_BroadcastAudio_StopOutputStream=EOSSDK_real.EOS_BroadcastAudio_StopOutputStream")
#pragma comment(linker, "/EXPORT:EOS_ByteArray_ToString=EOSSDK_real.EOS_ByteArray_ToString")
// EOS_Connect_* -> all stubbed (real DLL would crash on our fake Connect handle)
#pragma comment(linker, "/EXPORT:EOS_ContinuanceToken_ToString=EOSSDK_real.EOS_ContinuanceToken_ToString")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_AcceptRequestToJoin=EOSSDK_real.EOS_CustomInvites_AcceptRequestToJoin")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_AddNotifyCustomInviteAccepted=EOSSDK_real.EOS_CustomInvites_AddNotifyCustomInviteAccepted")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_AddNotifyCustomInviteReceived=EOSSDK_real.EOS_CustomInvites_AddNotifyCustomInviteReceived")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_AddNotifyCustomInviteRejected=EOSSDK_real.EOS_CustomInvites_AddNotifyCustomInviteRejected")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_AddNotifyRequestToJoinAccepted=EOSSDK_real.EOS_CustomInvites_AddNotifyRequestToJoinAccepted")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_AddNotifyRequestToJoinReceived=EOSSDK_real.EOS_CustomInvites_AddNotifyRequestToJoinReceived")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_AddNotifyRequestToJoinRejected=EOSSDK_real.EOS_CustomInvites_AddNotifyRequestToJoinRejected")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_AddNotifyRequestToJoinResponseReceived=EOSSDK_real.EOS_CustomInvites_AddNotifyRequestToJoinResponseReceived")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_AddNotifySendCustomNativeInviteRequested=EOSSDK_real.EOS_CustomInvites_AddNotifySendCustomNativeInviteRequested")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_FinalizeInvite=EOSSDK_real.EOS_CustomInvites_FinalizeInvite")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_RejectRequestToJoin=EOSSDK_real.EOS_CustomInvites_RejectRequestToJoin")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_RemoveNotifyCustomInviteAccepted=EOSSDK_real.EOS_CustomInvites_RemoveNotifyCustomInviteAccepted")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_RemoveNotifyCustomInviteReceived=EOSSDK_real.EOS_CustomInvites_RemoveNotifyCustomInviteReceived")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_RemoveNotifyCustomInviteRejected=EOSSDK_real.EOS_CustomInvites_RemoveNotifyCustomInviteRejected")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_RemoveNotifyRequestToJoinAccepted=EOSSDK_real.EOS_CustomInvites_RemoveNotifyRequestToJoinAccepted")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_RemoveNotifyRequestToJoinReceived=EOSSDK_real.EOS_CustomInvites_RemoveNotifyRequestToJoinReceived")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_RemoveNotifyRequestToJoinRejected=EOSSDK_real.EOS_CustomInvites_RemoveNotifyRequestToJoinRejected")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_RemoveNotifyRequestToJoinResponseReceived=EOSSDK_real.EOS_CustomInvites_RemoveNotifyRequestToJoinResponseReceived")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_RemoveNotifySendCustomNativeInviteRequested=EOSSDK_real.EOS_CustomInvites_RemoveNotifySendCustomNativeInviteRequested")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_SendCustomInvite=EOSSDK_real.EOS_CustomInvites_SendCustomInvite")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_SendRequestToJoin=EOSSDK_real.EOS_CustomInvites_SendRequestToJoin")
#pragma comment(linker, "/EXPORT:EOS_CustomInvites_SetCustomInvite=EOSSDK_real.EOS_CustomInvites_SetCustomInvite")
#pragma comment(linker, "/EXPORT:EOS_EApplicationStatus_ToString=EOSSDK_real.EOS_EApplicationStatus_ToString")
#pragma comment(linker, "/EXPORT:EOS_Ecom_CatalogItem_Release=EOSSDK_real.EOS_Ecom_CatalogItem_Release")
#pragma comment(linker, "/EXPORT:EOS_Ecom_CatalogOffer_Release=EOSSDK_real.EOS_Ecom_CatalogOffer_Release")
#pragma comment(linker, "/EXPORT:EOS_Ecom_CatalogRelease_Release=EOSSDK_real.EOS_Ecom_CatalogRelease_Release")
#pragma comment(linker, "/EXPORT:EOS_Ecom_Checkout=EOSSDK_real.EOS_Ecom_Checkout")
#pragma comment(linker, "/EXPORT:EOS_Ecom_CopyEntitlementById=EOSSDK_real.EOS_Ecom_CopyEntitlementById")
#pragma comment(linker, "/EXPORT:EOS_Ecom_CopyEntitlementByIndex=EOSSDK_real.EOS_Ecom_CopyEntitlementByIndex")
#pragma comment(linker, "/EXPORT:EOS_Ecom_CopyEntitlementByNameAndIndex=EOSSDK_real.EOS_Ecom_CopyEntitlementByNameAndIndex")
#pragma comment(linker, "/EXPORT:EOS_Ecom_CopyItemById=EOSSDK_real.EOS_Ecom_CopyItemById")
#pragma comment(linker, "/EXPORT:EOS_Ecom_CopyItemImageInfoByIndex=EOSSDK_real.EOS_Ecom_CopyItemImageInfoByIndex")
#pragma comment(linker, "/EXPORT:EOS_Ecom_CopyItemReleaseByIndex=EOSSDK_real.EOS_Ecom_CopyItemReleaseByIndex")
#pragma comment(linker, "/EXPORT:EOS_Ecom_CopyLastRedeemedEntitlementByIndex=EOSSDK_real.EOS_Ecom_CopyLastRedeemedEntitlementByIndex")
#pragma comment(linker, "/EXPORT:EOS_Ecom_CopyOfferById=EOSSDK_real.EOS_Ecom_CopyOfferById")
#pragma comment(linker, "/EXPORT:EOS_Ecom_CopyOfferByIndex=EOSSDK_real.EOS_Ecom_CopyOfferByIndex")
#pragma comment(linker, "/EXPORT:EOS_Ecom_CopyOfferImageInfoByIndex=EOSSDK_real.EOS_Ecom_CopyOfferImageInfoByIndex")
#pragma comment(linker, "/EXPORT:EOS_Ecom_CopyOfferItemByIndex=EOSSDK_real.EOS_Ecom_CopyOfferItemByIndex")
#pragma comment(linker, "/EXPORT:EOS_Ecom_CopyTransactionById=EOSSDK_real.EOS_Ecom_CopyTransactionById")
#pragma comment(linker, "/EXPORT:EOS_Ecom_CopyTransactionByIndex=EOSSDK_real.EOS_Ecom_CopyTransactionByIndex")
#pragma comment(linker, "/EXPORT:EOS_Ecom_Entitlement_Release=EOSSDK_real.EOS_Ecom_Entitlement_Release")
#pragma comment(linker, "/EXPORT:EOS_Ecom_GetEntitlementsByNameCount=EOSSDK_real.EOS_Ecom_GetEntitlementsByNameCount")
#pragma comment(linker, "/EXPORT:EOS_Ecom_GetEntitlementsCount=EOSSDK_real.EOS_Ecom_GetEntitlementsCount")
#pragma comment(linker, "/EXPORT:EOS_Ecom_GetItemImageInfoCount=EOSSDK_real.EOS_Ecom_GetItemImageInfoCount")
#pragma comment(linker, "/EXPORT:EOS_Ecom_GetItemReleaseCount=EOSSDK_real.EOS_Ecom_GetItemReleaseCount")
#pragma comment(linker, "/EXPORT:EOS_Ecom_GetLastRedeemedEntitlementsCount=EOSSDK_real.EOS_Ecom_GetLastRedeemedEntitlementsCount")
#pragma comment(linker, "/EXPORT:EOS_Ecom_GetOfferCount=EOSSDK_real.EOS_Ecom_GetOfferCount")
#pragma comment(linker, "/EXPORT:EOS_Ecom_GetOfferImageInfoCount=EOSSDK_real.EOS_Ecom_GetOfferImageInfoCount")
#pragma comment(linker, "/EXPORT:EOS_Ecom_GetOfferItemCount=EOSSDK_real.EOS_Ecom_GetOfferItemCount")
#pragma comment(linker, "/EXPORT:EOS_Ecom_GetTransactionCount=EOSSDK_real.EOS_Ecom_GetTransactionCount")
#pragma comment(linker, "/EXPORT:EOS_Ecom_KeyImageInfo_Release=EOSSDK_real.EOS_Ecom_KeyImageInfo_Release")
#pragma comment(linker, "/EXPORT:EOS_Ecom_QueryEntitlements=EOSSDK_real.EOS_Ecom_QueryEntitlements")
#pragma comment(linker, "/EXPORT:EOS_Ecom_QueryEntitlementToken=EOSSDK_real.EOS_Ecom_QueryEntitlementToken")
#pragma comment(linker, "/EXPORT:EOS_Ecom_QueryOffers=EOSSDK_real.EOS_Ecom_QueryOffers")
#pragma comment(linker, "/EXPORT:EOS_Ecom_QueryOwnership=EOSSDK_real.EOS_Ecom_QueryOwnership")
#pragma comment(linker, "/EXPORT:EOS_Ecom_QueryOwnershipBySandboxIds=EOSSDK_real.EOS_Ecom_QueryOwnershipBySandboxIds")
#pragma comment(linker, "/EXPORT:EOS_Ecom_QueryOwnershipToken=EOSSDK_real.EOS_Ecom_QueryOwnershipToken")
#pragma comment(linker, "/EXPORT:EOS_Ecom_RedeemEntitlements=EOSSDK_real.EOS_Ecom_RedeemEntitlements")
#pragma comment(linker, "/EXPORT:EOS_Ecom_Transaction_CopyEntitlementByIndex=EOSSDK_real.EOS_Ecom_Transaction_CopyEntitlementByIndex")
#pragma comment(linker, "/EXPORT:EOS_Ecom_Transaction_GetEntitlementsCount=EOSSDK_real.EOS_Ecom_Transaction_GetEntitlementsCount")
#pragma comment(linker, "/EXPORT:EOS_Ecom_Transaction_GetTransactionId=EOSSDK_real.EOS_Ecom_Transaction_GetTransactionId")
#pragma comment(linker, "/EXPORT:EOS_Ecom_Transaction_Release=EOSSDK_real.EOS_Ecom_Transaction_Release")
#pragma comment(linker, "/EXPORT:EOS_EndScopeEvent=EOSSDK_real.EOS_EndScopeEvent")
#pragma comment(linker, "/EXPORT:EOS_ENetworkStatus_ToString=EOSSDK_real.EOS_ENetworkStatus_ToString")
#pragma comment(linker, "/EXPORT:EOS_EpicAccountId_FromString=EOSSDK_real.EOS_EpicAccountId_FromString")
#pragma comment(linker, "/EXPORT:EOS_EpicAccountId_IsValid=EOSSDK_real.EOS_EpicAccountId_IsValid")
#pragma comment(linker, "/EXPORT:EOS_EpicAccountId_ToString=EOSSDK_real.EOS_EpicAccountId_ToString")
#pragma comment(linker, "/EXPORT:EOS_EResult_IsOperationComplete=EOSSDK_real.EOS_EResult_IsOperationComplete")
#pragma comment(linker, "/EXPORT:EOS_EResult_ToString=EOSSDK_real.EOS_EResult_ToString")
#pragma comment(linker, "/EXPORT:EOS_Friends_AcceptInvite=EOSSDK_real.EOS_Friends_AcceptInvite")
#pragma comment(linker, "/EXPORT:EOS_Friends_AddNotifyBlockedUsersUpdate=EOSSDK_real.EOS_Friends_AddNotifyBlockedUsersUpdate")
#pragma comment(linker, "/EXPORT:EOS_Friends_AddNotifyFriendsUpdate=EOSSDK_real.EOS_Friends_AddNotifyFriendsUpdate")
#pragma comment(linker, "/EXPORT:EOS_Friends_GetBlockedUserAtIndex=EOSSDK_real.EOS_Friends_GetBlockedUserAtIndex")
#pragma comment(linker, "/EXPORT:EOS_Friends_GetBlockedUsersCount=EOSSDK_real.EOS_Friends_GetBlockedUsersCount")
#pragma comment(linker, "/EXPORT:EOS_Friends_GetFriendAtIndex=EOSSDK_real.EOS_Friends_GetFriendAtIndex")
#pragma comment(linker, "/EXPORT:EOS_Friends_GetFriendsCount=EOSSDK_real.EOS_Friends_GetFriendsCount")
#pragma comment(linker, "/EXPORT:EOS_Friends_GetStatus=EOSSDK_real.EOS_Friends_GetStatus")
#pragma comment(linker, "/EXPORT:EOS_Friends_QueryFriends=EOSSDK_real.EOS_Friends_QueryFriends")
#pragma comment(linker, "/EXPORT:EOS_Friends_RejectInvite=EOSSDK_real.EOS_Friends_RejectInvite")
#pragma comment(linker, "/EXPORT:EOS_Friends_RemoveNotifyBlockedUsersUpdate=EOSSDK_real.EOS_Friends_RemoveNotifyBlockedUsersUpdate")
#pragma comment(linker, "/EXPORT:EOS_Friends_RemoveNotifyFriendsUpdate=EOSSDK_real.EOS_Friends_RemoveNotifyFriendsUpdate")
#pragma comment(linker, "/EXPORT:EOS_Friends_SendInvite=EOSSDK_real.EOS_Friends_SendInvite")
#pragma comment(linker, "/EXPORT:EOS_GetVersion=EOSSDK_real.EOS_GetVersion")
#pragma comment(linker, "/EXPORT:EOS_Initialize=EOSSDK_real.EOS_Initialize")
#pragma comment(linker, "/EXPORT:EOS_IntegratedPlatform_AddNotifyUserLoginStatusChanged=EOSSDK_real.EOS_IntegratedPlatform_AddNotifyUserLoginStatusChanged")
#pragma comment(linker, "/EXPORT:EOS_IntegratedPlatform_ClearUserPreLogoutCallback=EOSSDK_real.EOS_IntegratedPlatform_ClearUserPreLogoutCallback")
#pragma comment(linker, "/EXPORT:EOS_IntegratedPlatform_CreateIntegratedPlatformOptionsContainer=EOSSDK_real.EOS_IntegratedPlatform_CreateIntegratedPlatformOptionsContainer")
#pragma comment(linker, "/EXPORT:EOS_IntegratedPlatform_FinalizeDeferredUserLogout=EOSSDK_real.EOS_IntegratedPlatform_FinalizeDeferredUserLogout")
#pragma comment(linker, "/EXPORT:EOS_IntegratedPlatform_RemoveNotifyUserLoginStatusChanged=EOSSDK_real.EOS_IntegratedPlatform_RemoveNotifyUserLoginStatusChanged")
#pragma comment(linker, "/EXPORT:EOS_IntegratedPlatform_SetUserLoginStatus=EOSSDK_real.EOS_IntegratedPlatform_SetUserLoginStatus")
#pragma comment(linker, "/EXPORT:EOS_IntegratedPlatform_SetUserPreLogoutCallback=EOSSDK_real.EOS_IntegratedPlatform_SetUserPreLogoutCallback")
#pragma comment(linker, "/EXPORT:EOS_IntegratedPlatformOptionsContainer_Add=EOSSDK_real.EOS_IntegratedPlatformOptionsContainer_Add")
#pragma comment(linker, "/EXPORT:EOS_IntegratedPlatformOptionsContainer_Release=EOSSDK_real.EOS_IntegratedPlatformOptionsContainer_Release")
#pragma comment(linker, "/EXPORT:EOS_KWS_AddNotifyPermissionsUpdateReceived=EOSSDK_real.EOS_KWS_AddNotifyPermissionsUpdateReceived")
#pragma comment(linker, "/EXPORT:EOS_KWS_CopyPermissionByIndex=EOSSDK_real.EOS_KWS_CopyPermissionByIndex")
#pragma comment(linker, "/EXPORT:EOS_KWS_CreateUser=EOSSDK_real.EOS_KWS_CreateUser")
#pragma comment(linker, "/EXPORT:EOS_KWS_GetPermissionByKey=EOSSDK_real.EOS_KWS_GetPermissionByKey")
#pragma comment(linker, "/EXPORT:EOS_KWS_GetPermissionsCount=EOSSDK_real.EOS_KWS_GetPermissionsCount")
#pragma comment(linker, "/EXPORT:EOS_KWS_PermissionStatus_Release=EOSSDK_real.EOS_KWS_PermissionStatus_Release")
#pragma comment(linker, "/EXPORT:EOS_KWS_QueryAgeGate=EOSSDK_real.EOS_KWS_QueryAgeGate")
#pragma comment(linker, "/EXPORT:EOS_KWS_QueryPermissions=EOSSDK_real.EOS_KWS_QueryPermissions")
#pragma comment(linker, "/EXPORT:EOS_KWS_RemoveNotifyPermissionsUpdateReceived=EOSSDK_real.EOS_KWS_RemoveNotifyPermissionsUpdateReceived")
#pragma comment(linker, "/EXPORT:EOS_KWS_RequestPermissions=EOSSDK_real.EOS_KWS_RequestPermissions")
#pragma comment(linker, "/EXPORT:EOS_KWS_UpdateParentEmail=EOSSDK_real.EOS_KWS_UpdateParentEmail")
#pragma comment(linker, "/EXPORT:EOS_Leaderboards_CopyLeaderboardDefinitionByIndex=EOSSDK_real.EOS_Leaderboards_CopyLeaderboardDefinitionByIndex")
#pragma comment(linker, "/EXPORT:EOS_Leaderboards_CopyLeaderboardDefinitionByLeaderboardId=EOSSDK_real.EOS_Leaderboards_CopyLeaderboardDefinitionByLeaderboardId")
#pragma comment(linker, "/EXPORT:EOS_Leaderboards_CopyLeaderboardRecordByIndex=EOSSDK_real.EOS_Leaderboards_CopyLeaderboardRecordByIndex")
#pragma comment(linker, "/EXPORT:EOS_Leaderboards_CopyLeaderboardRecordByUserId=EOSSDK_real.EOS_Leaderboards_CopyLeaderboardRecordByUserId")
#pragma comment(linker, "/EXPORT:EOS_Leaderboards_CopyLeaderboardUserScoreByIndex=EOSSDK_real.EOS_Leaderboards_CopyLeaderboardUserScoreByIndex")
#pragma comment(linker, "/EXPORT:EOS_Leaderboards_CopyLeaderboardUserScoreByUserId=EOSSDK_real.EOS_Leaderboards_CopyLeaderboardUserScoreByUserId")
#pragma comment(linker, "/EXPORT:EOS_Leaderboards_Definition_Release=EOSSDK_real.EOS_Leaderboards_Definition_Release")
#pragma comment(linker, "/EXPORT:EOS_Leaderboards_GetLeaderboardDefinitionCount=EOSSDK_real.EOS_Leaderboards_GetLeaderboardDefinitionCount")
#pragma comment(linker, "/EXPORT:EOS_Leaderboards_GetLeaderboardRecordCount=EOSSDK_real.EOS_Leaderboards_GetLeaderboardRecordCount")
#pragma comment(linker, "/EXPORT:EOS_Leaderboards_GetLeaderboardUserScoreCount=EOSSDK_real.EOS_Leaderboards_GetLeaderboardUserScoreCount")
#pragma comment(linker, "/EXPORT:EOS_Leaderboards_LeaderboardDefinition_Release=EOSSDK_real.EOS_Leaderboards_LeaderboardDefinition_Release")
#pragma comment(linker, "/EXPORT:EOS_Leaderboards_LeaderboardRecord_Release=EOSSDK_real.EOS_Leaderboards_LeaderboardRecord_Release")
#pragma comment(linker, "/EXPORT:EOS_Leaderboards_LeaderboardUserScore_Release=EOSSDK_real.EOS_Leaderboards_LeaderboardUserScore_Release")
#pragma comment(linker, "/EXPORT:EOS_Leaderboards_QueryLeaderboardDefinitions=EOSSDK_real.EOS_Leaderboards_QueryLeaderboardDefinitions")
#pragma comment(linker, "/EXPORT:EOS_Leaderboards_QueryLeaderboardRanks=EOSSDK_real.EOS_Leaderboards_QueryLeaderboardRanks")
#pragma comment(linker, "/EXPORT:EOS_Leaderboards_QueryLeaderboardUserScores=EOSSDK_real.EOS_Leaderboards_QueryLeaderboardUserScores")
#pragma comment(linker, "/EXPORT:EOS_Lobby_AddNotifyJoinLobbyAccepted=EOSSDK_real.EOS_Lobby_AddNotifyJoinLobbyAccepted")
#pragma comment(linker, "/EXPORT:EOS_Lobby_AddNotifyLeaveLobbyRequested=EOSSDK_real.EOS_Lobby_AddNotifyLeaveLobbyRequested")
#pragma comment(linker, "/EXPORT:EOS_Lobby_AddNotifyLobbyInviteAccepted=EOSSDK_real.EOS_Lobby_AddNotifyLobbyInviteAccepted")
#pragma comment(linker, "/EXPORT:EOS_Lobby_AddNotifyLobbyInviteReceived=EOSSDK_real.EOS_Lobby_AddNotifyLobbyInviteReceived")
#pragma comment(linker, "/EXPORT:EOS_Lobby_AddNotifyLobbyInviteRejected=EOSSDK_real.EOS_Lobby_AddNotifyLobbyInviteRejected")
#pragma comment(linker, "/EXPORT:EOS_Lobby_AddNotifyLobbyMemberStatusReceived=EOSSDK_real.EOS_Lobby_AddNotifyLobbyMemberStatusReceived")
#pragma comment(linker, "/EXPORT:EOS_Lobby_AddNotifyLobbyMemberUpdateReceived=EOSSDK_real.EOS_Lobby_AddNotifyLobbyMemberUpdateReceived")
#pragma comment(linker, "/EXPORT:EOS_Lobby_AddNotifyLobbyUpdateReceived=EOSSDK_real.EOS_Lobby_AddNotifyLobbyUpdateReceived")
#pragma comment(linker, "/EXPORT:EOS_Lobby_AddNotifyRTCRoomConnectionChanged=EOSSDK_real.EOS_Lobby_AddNotifyRTCRoomConnectionChanged")
#pragma comment(linker, "/EXPORT:EOS_Lobby_AddNotifySendLobbyNativeInviteRequested=EOSSDK_real.EOS_Lobby_AddNotifySendLobbyNativeInviteRequested")
#pragma comment(linker, "/EXPORT:EOS_Lobby_Attribute_Release=EOSSDK_real.EOS_Lobby_Attribute_Release")
#pragma comment(linker, "/EXPORT:EOS_Lobby_CopyLobbyDetailsHandle=EOSSDK_real.EOS_Lobby_CopyLobbyDetailsHandle")
#pragma comment(linker, "/EXPORT:EOS_Lobby_CopyLobbyDetailsHandleByInviteId=EOSSDK_real.EOS_Lobby_CopyLobbyDetailsHandleByInviteId")
#pragma comment(linker, "/EXPORT:EOS_Lobby_CopyLobbyDetailsHandleByUiEventId=EOSSDK_real.EOS_Lobby_CopyLobbyDetailsHandleByUiEventId")
#pragma comment(linker, "/EXPORT:EOS_Lobby_CreateLobby=EOSSDK_real.EOS_Lobby_CreateLobby")
#pragma comment(linker, "/EXPORT:EOS_Lobby_CreateLobbySearch=EOSSDK_real.EOS_Lobby_CreateLobbySearch")
#pragma comment(linker, "/EXPORT:EOS_Lobby_DestroyLobby=EOSSDK_real.EOS_Lobby_DestroyLobby")
#pragma comment(linker, "/EXPORT:EOS_Lobby_GetConnectString=EOSSDK_real.EOS_Lobby_GetConnectString")
#pragma comment(linker, "/EXPORT:EOS_Lobby_GetInviteCount=EOSSDK_real.EOS_Lobby_GetInviteCount")
#pragma comment(linker, "/EXPORT:EOS_Lobby_GetInviteIdByIndex=EOSSDK_real.EOS_Lobby_GetInviteIdByIndex")
#pragma comment(linker, "/EXPORT:EOS_Lobby_GetRTCRoomName=EOSSDK_real.EOS_Lobby_GetRTCRoomName")
#pragma comment(linker, "/EXPORT:EOS_Lobby_HardMuteMember=EOSSDK_real.EOS_Lobby_HardMuteMember")
#pragma comment(linker, "/EXPORT:EOS_Lobby_IsRTCRoomConnected=EOSSDK_real.EOS_Lobby_IsRTCRoomConnected")
#pragma comment(linker, "/EXPORT:EOS_Lobby_JoinLobby=EOSSDK_real.EOS_Lobby_JoinLobby")
#pragma comment(linker, "/EXPORT:EOS_Lobby_JoinLobbyById=EOSSDK_real.EOS_Lobby_JoinLobbyById")
#pragma comment(linker, "/EXPORT:EOS_Lobby_JoinRTCRoom=EOSSDK_real.EOS_Lobby_JoinRTCRoom")
#pragma comment(linker, "/EXPORT:EOS_Lobby_KickMember=EOSSDK_real.EOS_Lobby_KickMember")
#pragma comment(linker, "/EXPORT:EOS_Lobby_LeaveLobby=EOSSDK_real.EOS_Lobby_LeaveLobby")
#pragma comment(linker, "/EXPORT:EOS_Lobby_LeaveRTCRoom=EOSSDK_real.EOS_Lobby_LeaveRTCRoom")
#pragma comment(linker, "/EXPORT:EOS_Lobby_ParseConnectString=EOSSDK_real.EOS_Lobby_ParseConnectString")
#pragma comment(linker, "/EXPORT:EOS_Lobby_PromoteMember=EOSSDK_real.EOS_Lobby_PromoteMember")
#pragma comment(linker, "/EXPORT:EOS_Lobby_QueryInvites=EOSSDK_real.EOS_Lobby_QueryInvites")
#pragma comment(linker, "/EXPORT:EOS_Lobby_RejectInvite=EOSSDK_real.EOS_Lobby_RejectInvite")
#pragma comment(linker, "/EXPORT:EOS_Lobby_RemoveNotifyJoinLobbyAccepted=EOSSDK_real.EOS_Lobby_RemoveNotifyJoinLobbyAccepted")
#pragma comment(linker, "/EXPORT:EOS_Lobby_RemoveNotifyLeaveLobbyRequested=EOSSDK_real.EOS_Lobby_RemoveNotifyLeaveLobbyRequested")
#pragma comment(linker, "/EXPORT:EOS_Lobby_RemoveNotifyLobbyInviteAccepted=EOSSDK_real.EOS_Lobby_RemoveNotifyLobbyInviteAccepted")
#pragma comment(linker, "/EXPORT:EOS_Lobby_RemoveNotifyLobbyInviteReceived=EOSSDK_real.EOS_Lobby_RemoveNotifyLobbyInviteReceived")
#pragma comment(linker, "/EXPORT:EOS_Lobby_RemoveNotifyLobbyInviteRejected=EOSSDK_real.EOS_Lobby_RemoveNotifyLobbyInviteRejected")
#pragma comment(linker, "/EXPORT:EOS_Lobby_RemoveNotifyLobbyMemberStatusReceived=EOSSDK_real.EOS_Lobby_RemoveNotifyLobbyMemberStatusReceived")
#pragma comment(linker, "/EXPORT:EOS_Lobby_RemoveNotifyLobbyMemberUpdateReceived=EOSSDK_real.EOS_Lobby_RemoveNotifyLobbyMemberUpdateReceived")
#pragma comment(linker, "/EXPORT:EOS_Lobby_RemoveNotifyLobbyUpdateReceived=EOSSDK_real.EOS_Lobby_RemoveNotifyLobbyUpdateReceived")
#pragma comment(linker, "/EXPORT:EOS_Lobby_RemoveNotifyRTCRoomConnectionChanged=EOSSDK_real.EOS_Lobby_RemoveNotifyRTCRoomConnectionChanged")
#pragma comment(linker, "/EXPORT:EOS_Lobby_RemoveNotifySendLobbyNativeInviteRequested=EOSSDK_real.EOS_Lobby_RemoveNotifySendLobbyNativeInviteRequested")
#pragma comment(linker, "/EXPORT:EOS_Lobby_SendInvite=EOSSDK_real.EOS_Lobby_SendInvite")
#pragma comment(linker, "/EXPORT:EOS_Lobby_UpdateLobby=EOSSDK_real.EOS_Lobby_UpdateLobby")
#pragma comment(linker, "/EXPORT:EOS_Lobby_UpdateLobbyModification=EOSSDK_real.EOS_Lobby_UpdateLobbyModification")
#pragma comment(linker, "/EXPORT:EOS_LobbyDetails_CopyAttributeByIndex=EOSSDK_real.EOS_LobbyDetails_CopyAttributeByIndex")
#pragma comment(linker, "/EXPORT:EOS_LobbyDetails_CopyAttributeByKey=EOSSDK_real.EOS_LobbyDetails_CopyAttributeByKey")
#pragma comment(linker, "/EXPORT:EOS_LobbyDetails_CopyInfo=EOSSDK_real.EOS_LobbyDetails_CopyInfo")
#pragma comment(linker, "/EXPORT:EOS_LobbyDetails_CopyMemberAttributeByIndex=EOSSDK_real.EOS_LobbyDetails_CopyMemberAttributeByIndex")
#pragma comment(linker, "/EXPORT:EOS_LobbyDetails_CopyMemberAttributeByKey=EOSSDK_real.EOS_LobbyDetails_CopyMemberAttributeByKey")
#pragma comment(linker, "/EXPORT:EOS_LobbyDetails_CopyMemberInfo=EOSSDK_real.EOS_LobbyDetails_CopyMemberInfo")
#pragma comment(linker, "/EXPORT:EOS_LobbyDetails_GetAttributeCount=EOSSDK_real.EOS_LobbyDetails_GetAttributeCount")
#pragma comment(linker, "/EXPORT:EOS_LobbyDetails_GetLobbyOwner=EOSSDK_real.EOS_LobbyDetails_GetLobbyOwner")
#pragma comment(linker, "/EXPORT:EOS_LobbyDetails_GetMemberAttributeCount=EOSSDK_real.EOS_LobbyDetails_GetMemberAttributeCount")
#pragma comment(linker, "/EXPORT:EOS_LobbyDetails_GetMemberByIndex=EOSSDK_real.EOS_LobbyDetails_GetMemberByIndex")
#pragma comment(linker, "/EXPORT:EOS_LobbyDetails_GetMemberCount=EOSSDK_real.EOS_LobbyDetails_GetMemberCount")
#pragma comment(linker, "/EXPORT:EOS_LobbyDetails_Info_Release=EOSSDK_real.EOS_LobbyDetails_Info_Release")
#pragma comment(linker, "/EXPORT:EOS_LobbyDetails_MemberInfo_Release=EOSSDK_real.EOS_LobbyDetails_MemberInfo_Release")
#pragma comment(linker, "/EXPORT:EOS_LobbyDetails_Release=EOSSDK_real.EOS_LobbyDetails_Release")
#pragma comment(linker, "/EXPORT:EOS_LobbyModification_AddAttribute=EOSSDK_real.EOS_LobbyModification_AddAttribute")
#pragma comment(linker, "/EXPORT:EOS_LobbyModification_AddMemberAttribute=EOSSDK_real.EOS_LobbyModification_AddMemberAttribute")
#pragma comment(linker, "/EXPORT:EOS_LobbyModification_Release=EOSSDK_real.EOS_LobbyModification_Release")
#pragma comment(linker, "/EXPORT:EOS_LobbyModification_RemoveAttribute=EOSSDK_real.EOS_LobbyModification_RemoveAttribute")
#pragma comment(linker, "/EXPORT:EOS_LobbyModification_RemoveMemberAttribute=EOSSDK_real.EOS_LobbyModification_RemoveMemberAttribute")
#pragma comment(linker, "/EXPORT:EOS_LobbyModification_SetAllowedPlatformIds=EOSSDK_real.EOS_LobbyModification_SetAllowedPlatformIds")
#pragma comment(linker, "/EXPORT:EOS_LobbyModification_SetBucketId=EOSSDK_real.EOS_LobbyModification_SetBucketId")
#pragma comment(linker, "/EXPORT:EOS_LobbyModification_SetInvitesAllowed=EOSSDK_real.EOS_LobbyModification_SetInvitesAllowed")
#pragma comment(linker, "/EXPORT:EOS_LobbyModification_SetMaxMembers=EOSSDK_real.EOS_LobbyModification_SetMaxMembers")
#pragma comment(linker, "/EXPORT:EOS_LobbyModification_SetPermissionLevel=EOSSDK_real.EOS_LobbyModification_SetPermissionLevel")
#pragma comment(linker, "/EXPORT:EOS_LobbySearch_CopySearchResultByIndex=EOSSDK_real.EOS_LobbySearch_CopySearchResultByIndex")
#pragma comment(linker, "/EXPORT:EOS_LobbySearch_Find=EOSSDK_real.EOS_LobbySearch_Find")
#pragma comment(linker, "/EXPORT:EOS_LobbySearch_GetSearchResultCount=EOSSDK_real.EOS_LobbySearch_GetSearchResultCount")
#pragma comment(linker, "/EXPORT:EOS_LobbySearch_Release=EOSSDK_real.EOS_LobbySearch_Release")
#pragma comment(linker, "/EXPORT:EOS_LobbySearch_RemoveParameter=EOSSDK_real.EOS_LobbySearch_RemoveParameter")
#pragma comment(linker, "/EXPORT:EOS_LobbySearch_SetLobbyId=EOSSDK_real.EOS_LobbySearch_SetLobbyId")
#pragma comment(linker, "/EXPORT:EOS_LobbySearch_SetMaxResults=EOSSDK_real.EOS_LobbySearch_SetMaxResults")
#pragma comment(linker, "/EXPORT:EOS_LobbySearch_SetParameter=EOSSDK_real.EOS_LobbySearch_SetParameter")
#pragma comment(linker, "/EXPORT:EOS_LobbySearch_SetTargetUserId=EOSSDK_real.EOS_LobbySearch_SetTargetUserId")
#pragma comment(linker, "/EXPORT:EOS_Logging_SetCallback=EOSSDK_real.EOS_Logging_SetCallback")
#pragma comment(linker, "/EXPORT:EOS_Logging_SetLogLevel=EOSSDK_real.EOS_Logging_SetLogLevel")
#pragma comment(linker, "/EXPORT:EOS_Mercury_Initialize=EOSSDK_real.EOS_Mercury_Initialize")
#pragma comment(linker, "/EXPORT:EOS_Mercury_Shutdown=EOSSDK_real.EOS_Mercury_Shutdown")
#pragma comment(linker, "/EXPORT:EOS_Mercury_Tick=EOSSDK_real.EOS_Mercury_Tick")
#pragma comment(linker, "/EXPORT:EOS_Metrics_BeginPlayerSession=EOSSDK_real.EOS_Metrics_BeginPlayerSession")
#pragma comment(linker, "/EXPORT:EOS_Metrics_EndPlayerSession=EOSSDK_real.EOS_Metrics_EndPlayerSession")
#pragma comment(linker, "/EXPORT:EOS_Mods_CopyModInfo=EOSSDK_real.EOS_Mods_CopyModInfo")
#pragma comment(linker, "/EXPORT:EOS_Mods_EnumerateMods=EOSSDK_real.EOS_Mods_EnumerateMods")
#pragma comment(linker, "/EXPORT:EOS_Mods_InstallMod=EOSSDK_real.EOS_Mods_InstallMod")
#pragma comment(linker, "/EXPORT:EOS_Mods_ModInfo_Release=EOSSDK_real.EOS_Mods_ModInfo_Release")
#pragma comment(linker, "/EXPORT:EOS_Mods_UninstallMod=EOSSDK_real.EOS_Mods_UninstallMod")
#pragma comment(linker, "/EXPORT:EOS_Mods_UpdateMod=EOSSDK_real.EOS_Mods_UpdateMod")
#pragma comment(linker, "/EXPORT:EOS_P2P_AcceptConnection=EOSSDK_real.EOS_P2P_AcceptConnection")
#pragma comment(linker, "/EXPORT:EOS_P2P_AddNotifyIncomingPacketQueueFull=EOSSDK_real.EOS_P2P_AddNotifyIncomingPacketQueueFull")
#pragma comment(linker, "/EXPORT:EOS_P2P_AddNotifyPeerConnectionClosed=EOSSDK_real.EOS_P2P_AddNotifyPeerConnectionClosed")
#pragma comment(linker, "/EXPORT:EOS_P2P_AddNotifyPeerConnectionEstablished=EOSSDK_real.EOS_P2P_AddNotifyPeerConnectionEstablished")
#pragma comment(linker, "/EXPORT:EOS_P2P_AddNotifyPeerConnectionInterrupted=EOSSDK_real.EOS_P2P_AddNotifyPeerConnectionInterrupted")
#pragma comment(linker, "/EXPORT:EOS_P2P_AddNotifyPeerConnectionRequest=EOSSDK_real.EOS_P2P_AddNotifyPeerConnectionRequest")
#pragma comment(linker, "/EXPORT:EOS_P2P_ClearPacketQueue=EOSSDK_real.EOS_P2P_ClearPacketQueue")
#pragma comment(linker, "/EXPORT:EOS_P2P_CloseConnection=EOSSDK_real.EOS_P2P_CloseConnection")
#pragma comment(linker, "/EXPORT:EOS_P2P_CloseConnections=EOSSDK_real.EOS_P2P_CloseConnections")
#pragma comment(linker, "/EXPORT:EOS_P2P_GetNATType=EOSSDK_real.EOS_P2P_GetNATType")
#pragma comment(linker, "/EXPORT:EOS_P2P_GetNextReceivedPacketSize=EOSSDK_real.EOS_P2P_GetNextReceivedPacketSize")
#pragma comment(linker, "/EXPORT:EOS_P2P_GetPacketQueueInfo=EOSSDK_real.EOS_P2P_GetPacketQueueInfo")
#pragma comment(linker, "/EXPORT:EOS_P2P_GetPortRange=EOSSDK_real.EOS_P2P_GetPortRange")
#pragma comment(linker, "/EXPORT:EOS_P2P_GetRelayControl=EOSSDK_real.EOS_P2P_GetRelayControl")
#pragma comment(linker, "/EXPORT:EOS_P2P_QueryNATType=EOSSDK_real.EOS_P2P_QueryNATType")
#pragma comment(linker, "/EXPORT:EOS_P2P_ReceivePacket=EOSSDK_real.EOS_P2P_ReceivePacket")
#pragma comment(linker, "/EXPORT:EOS_P2P_RemoveNotifyIncomingPacketQueueFull=EOSSDK_real.EOS_P2P_RemoveNotifyIncomingPacketQueueFull")
#pragma comment(linker, "/EXPORT:EOS_P2P_RemoveNotifyPeerConnectionClosed=EOSSDK_real.EOS_P2P_RemoveNotifyPeerConnectionClosed")
#pragma comment(linker, "/EXPORT:EOS_P2P_RemoveNotifyPeerConnectionEstablished=EOSSDK_real.EOS_P2P_RemoveNotifyPeerConnectionEstablished")
#pragma comment(linker, "/EXPORT:EOS_P2P_RemoveNotifyPeerConnectionInterrupted=EOSSDK_real.EOS_P2P_RemoveNotifyPeerConnectionInterrupted")
#pragma comment(linker, "/EXPORT:EOS_P2P_RemoveNotifyPeerConnectionRequest=EOSSDK_real.EOS_P2P_RemoveNotifyPeerConnectionRequest")
#pragma comment(linker, "/EXPORT:EOS_P2P_SendPacket=EOSSDK_real.EOS_P2P_SendPacket")
#pragma comment(linker, "/EXPORT:EOS_P2P_SetPacketQueueSize=EOSSDK_real.EOS_P2P_SetPacketQueueSize")
#pragma comment(linker, "/EXPORT:EOS_P2P_SetPortRange=EOSSDK_real.EOS_P2P_SetPortRange")
#pragma comment(linker, "/EXPORT:EOS_P2P_SetRelayControl=EOSSDK_real.EOS_P2P_SetRelayControl")
// ALL EOS_Platform_* functions are stubbed below.
// EOS_Platform_Create returns a fake handle -> no real EOS platform is ever created
// -> no internal EAC auth threads start -> no "Failed login" popup.
// All Get*Interface stubs return null; the real DLL's module functions (EOS_Auth_Login etc.)
// safely return EOS_InvalidParameters on a null handle rather than crashing.
#pragma comment(linker, "/EXPORT:EOS_PlayerDataStorage_CopyFileMetadataAtIndex=EOSSDK_real.EOS_PlayerDataStorage_CopyFileMetadataAtIndex")
#pragma comment(linker, "/EXPORT:EOS_PlayerDataStorage_CopyFileMetadataByFilename=EOSSDK_real.EOS_PlayerDataStorage_CopyFileMetadataByFilename")
#pragma comment(linker, "/EXPORT:EOS_PlayerDataStorage_DeleteCache=EOSSDK_real.EOS_PlayerDataStorage_DeleteCache")
#pragma comment(linker, "/EXPORT:EOS_PlayerDataStorage_DeleteFile=EOSSDK_real.EOS_PlayerDataStorage_DeleteFile")
#pragma comment(linker, "/EXPORT:EOS_PlayerDataStorage_DuplicateFile=EOSSDK_real.EOS_PlayerDataStorage_DuplicateFile")
#pragma comment(linker, "/EXPORT:EOS_PlayerDataStorage_FileMetadata_Release=EOSSDK_real.EOS_PlayerDataStorage_FileMetadata_Release")
#pragma comment(linker, "/EXPORT:EOS_PlayerDataStorage_GetFileMetadataCount=EOSSDK_real.EOS_PlayerDataStorage_GetFileMetadataCount")
#pragma comment(linker, "/EXPORT:EOS_PlayerDataStorage_QueryFile=EOSSDK_real.EOS_PlayerDataStorage_QueryFile")
#pragma comment(linker, "/EXPORT:EOS_PlayerDataStorage_QueryFileList=EOSSDK_real.EOS_PlayerDataStorage_QueryFileList")
#pragma comment(linker, "/EXPORT:EOS_PlayerDataStorage_ReadFile=EOSSDK_real.EOS_PlayerDataStorage_ReadFile")
#pragma comment(linker, "/EXPORT:EOS_PlayerDataStorage_WriteFile=EOSSDK_real.EOS_PlayerDataStorage_WriteFile")
#pragma comment(linker, "/EXPORT:EOS_PlayerDataStorageFileTransferRequest_CancelRequest=EOSSDK_real.EOS_PlayerDataStorageFileTransferRequest_CancelRequest")
#pragma comment(linker, "/EXPORT:EOS_PlayerDataStorageFileTransferRequest_GetFilename=EOSSDK_real.EOS_PlayerDataStorageFileTransferRequest_GetFilename")
#pragma comment(linker, "/EXPORT:EOS_PlayerDataStorageFileTransferRequest_GetFileRequestState=EOSSDK_real.EOS_PlayerDataStorageFileTransferRequest_GetFileRequestState")
#pragma comment(linker, "/EXPORT:EOS_PlayerDataStorageFileTransferRequest_Release=EOSSDK_real.EOS_PlayerDataStorageFileTransferRequest_Release")
#pragma comment(linker, "/EXPORT:EOS_Presence_AddNotifyJoinGameAccepted=EOSSDK_real.EOS_Presence_AddNotifyJoinGameAccepted")
#pragma comment(linker, "/EXPORT:EOS_Presence_AddNotifyOnPresenceChanged=EOSSDK_real.EOS_Presence_AddNotifyOnPresenceChanged")
#pragma comment(linker, "/EXPORT:EOS_Presence_CopyPresence=EOSSDK_real.EOS_Presence_CopyPresence")
#pragma comment(linker, "/EXPORT:EOS_Presence_CreatePresenceModification=EOSSDK_real.EOS_Presence_CreatePresenceModification")
#pragma comment(linker, "/EXPORT:EOS_Presence_GetJoinInfo=EOSSDK_real.EOS_Presence_GetJoinInfo")
#pragma comment(linker, "/EXPORT:EOS_Presence_HasPresence=EOSSDK_real.EOS_Presence_HasPresence")
#pragma comment(linker, "/EXPORT:EOS_Presence_Info_Release=EOSSDK_real.EOS_Presence_Info_Release")
#pragma comment(linker, "/EXPORT:EOS_Presence_QueryPresence=EOSSDK_real.EOS_Presence_QueryPresence")
#pragma comment(linker, "/EXPORT:EOS_Presence_RemoveNotifyJoinGameAccepted=EOSSDK_real.EOS_Presence_RemoveNotifyJoinGameAccepted")
#pragma comment(linker, "/EXPORT:EOS_Presence_RemoveNotifyOnPresenceChanged=EOSSDK_real.EOS_Presence_RemoveNotifyOnPresenceChanged")
#pragma comment(linker, "/EXPORT:EOS_Presence_SetPresence=EOSSDK_real.EOS_Presence_SetPresence")
#pragma comment(linker, "/EXPORT:EOS_PresenceModification_DeleteData=EOSSDK_real.EOS_PresenceModification_DeleteData")
#pragma comment(linker, "/EXPORT:EOS_PresenceModification_Release=EOSSDK_real.EOS_PresenceModification_Release")
#pragma comment(linker, "/EXPORT:EOS_PresenceModification_SetData=EOSSDK_real.EOS_PresenceModification_SetData")
#pragma comment(linker, "/EXPORT:EOS_PresenceModification_SetJoinInfo=EOSSDK_real.EOS_PresenceModification_SetJoinInfo")
#pragma comment(linker, "/EXPORT:EOS_PresenceModification_SetRawRichText=EOSSDK_real.EOS_PresenceModification_SetRawRichText")
#pragma comment(linker, "/EXPORT:EOS_PresenceModification_SetStatus=EOSSDK_real.EOS_PresenceModification_SetStatus")
#pragma comment(linker, "/EXPORT:EOS_ProductUserId_FromString=EOSSDK_real.EOS_ProductUserId_FromString")
#pragma comment(linker, "/EXPORT:EOS_ProductUserId_IsValid=EOSSDK_real.EOS_ProductUserId_IsValid")
#pragma comment(linker, "/EXPORT:EOS_ProductUserId_ToString=EOSSDK_real.EOS_ProductUserId_ToString")
#pragma comment(linker, "/EXPORT:EOS_ProgressionSnapshot_AddProgression=EOSSDK_real.EOS_ProgressionSnapshot_AddProgression")
#pragma comment(linker, "/EXPORT:EOS_ProgressionSnapshot_BeginSnapshot=EOSSDK_real.EOS_ProgressionSnapshot_BeginSnapshot")
#pragma comment(linker, "/EXPORT:EOS_ProgressionSnapshot_DeleteSnapshot=EOSSDK_real.EOS_ProgressionSnapshot_DeleteSnapshot")
#pragma comment(linker, "/EXPORT:EOS_ProgressionSnapshot_EndSnapshot=EOSSDK_real.EOS_ProgressionSnapshot_EndSnapshot")
#pragma comment(linker, "/EXPORT:EOS_ProgressionSnapshot_SubmitSnapshot=EOSSDK_real.EOS_ProgressionSnapshot_SubmitSnapshot")
#pragma comment(linker, "/EXPORT:EOS_Reports_SendPlayerBehaviorReport=EOSSDK_real.EOS_Reports_SendPlayerBehaviorReport")
#pragma comment(linker, "/EXPORT:EOS_RTC_AddNotifyDisconnected=EOSSDK_real.EOS_RTC_AddNotifyDisconnected")
#pragma comment(linker, "/EXPORT:EOS_RTC_AddNotifyParticipantStatusChanged=EOSSDK_real.EOS_RTC_AddNotifyParticipantStatusChanged")
#pragma comment(linker, "/EXPORT:EOS_RTC_AddNotifyRoomStatisticsUpdated=EOSSDK_real.EOS_RTC_AddNotifyRoomStatisticsUpdated")
#pragma comment(linker, "/EXPORT:EOS_RTC_BlockParticipant=EOSSDK_real.EOS_RTC_BlockParticipant")
#pragma comment(linker, "/EXPORT:EOS_RTC_GetAudioInterface=EOSSDK_real.EOS_RTC_GetAudioInterface")
#pragma comment(linker, "/EXPORT:EOS_RTC_GetDataInterface=EOSSDK_real.EOS_RTC_GetDataInterface")
#pragma comment(linker, "/EXPORT:EOS_RTC_JoinRoom=EOSSDK_real.EOS_RTC_JoinRoom")
#pragma comment(linker, "/EXPORT:EOS_RTC_LeaveRoom=EOSSDK_real.EOS_RTC_LeaveRoom")
#pragma comment(linker, "/EXPORT:EOS_RTC_RemoveNotifyDisconnected=EOSSDK_real.EOS_RTC_RemoveNotifyDisconnected")
#pragma comment(linker, "/EXPORT:EOS_RTC_RemoveNotifyParticipantStatusChanged=EOSSDK_real.EOS_RTC_RemoveNotifyParticipantStatusChanged")
#pragma comment(linker, "/EXPORT:EOS_RTC_RemoveNotifyRoomStatisticsUpdated=EOSSDK_real.EOS_RTC_RemoveNotifyRoomStatisticsUpdated")
#pragma comment(linker, "/EXPORT:EOS_RTC_SetRoomSetting=EOSSDK_real.EOS_RTC_SetRoomSetting")
#pragma comment(linker, "/EXPORT:EOS_RTC_SetSetting=EOSSDK_real.EOS_RTC_SetSetting")
#pragma comment(linker, "/EXPORT:EOS_RTCAdmin_CopyUserTokenByIndex=EOSSDK_real.EOS_RTCAdmin_CopyUserTokenByIndex")
#pragma comment(linker, "/EXPORT:EOS_RTCAdmin_CopyUserTokenByUserId=EOSSDK_real.EOS_RTCAdmin_CopyUserTokenByUserId")
#pragma comment(linker, "/EXPORT:EOS_RTCAdmin_Kick=EOSSDK_real.EOS_RTCAdmin_Kick")
#pragma comment(linker, "/EXPORT:EOS_RTCAdmin_QueryJoinRoomToken=EOSSDK_real.EOS_RTCAdmin_QueryJoinRoomToken")
#pragma comment(linker, "/EXPORT:EOS_RTCAdmin_SetParticipantHardMute=EOSSDK_real.EOS_RTCAdmin_SetParticipantHardMute")
#pragma comment(linker, "/EXPORT:EOS_RTCAdmin_UserToken_Release=EOSSDK_real.EOS_RTCAdmin_UserToken_Release")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_AddNotifyAudioBeforeRender=EOSSDK_real.EOS_RTCAudio_AddNotifyAudioBeforeRender")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_AddNotifyAudioBeforeSend=EOSSDK_real.EOS_RTCAudio_AddNotifyAudioBeforeSend")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_AddNotifyAudioDevicesChanged=EOSSDK_real.EOS_RTCAudio_AddNotifyAudioDevicesChanged")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_AddNotifyAudioInputState=EOSSDK_real.EOS_RTCAudio_AddNotifyAudioInputState")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_AddNotifyAudioOutputState=EOSSDK_real.EOS_RTCAudio_AddNotifyAudioOutputState")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_AddNotifyParticipantUpdated=EOSSDK_real.EOS_RTCAudio_AddNotifyParticipantUpdated")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_CopyInputDeviceInformationByIndex=EOSSDK_real.EOS_RTCAudio_CopyInputDeviceInformationByIndex")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_CopyOutputDeviceInformationByIndex=EOSSDK_real.EOS_RTCAudio_CopyOutputDeviceInformationByIndex")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_GetAudioInputDeviceByIndex=EOSSDK_real.EOS_RTCAudio_GetAudioInputDeviceByIndex")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_GetAudioInputDevicesCount=EOSSDK_real.EOS_RTCAudio_GetAudioInputDevicesCount")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_GetAudioOutputDeviceByIndex=EOSSDK_real.EOS_RTCAudio_GetAudioOutputDeviceByIndex")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_GetAudioOutputDevicesCount=EOSSDK_real.EOS_RTCAudio_GetAudioOutputDevicesCount")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_GetInputDevicesCount=EOSSDK_real.EOS_RTCAudio_GetInputDevicesCount")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_GetOutputDevicesCount=EOSSDK_real.EOS_RTCAudio_GetOutputDevicesCount")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_InputDeviceInformation_Release=EOSSDK_real.EOS_RTCAudio_InputDeviceInformation_Release")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_OutputDeviceInformation_Release=EOSSDK_real.EOS_RTCAudio_OutputDeviceInformation_Release")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_QueryInputDevicesInformation=EOSSDK_real.EOS_RTCAudio_QueryInputDevicesInformation")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_QueryOutputDevicesInformation=EOSSDK_real.EOS_RTCAudio_QueryOutputDevicesInformation")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_RegisterPlatformAudioUser=EOSSDK_real.EOS_RTCAudio_RegisterPlatformAudioUser")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_RegisterPlatformUser=EOSSDK_real.EOS_RTCAudio_RegisterPlatformUser")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_RemoveNotifyAudioBeforeRender=EOSSDK_real.EOS_RTCAudio_RemoveNotifyAudioBeforeRender")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_RemoveNotifyAudioBeforeSend=EOSSDK_real.EOS_RTCAudio_RemoveNotifyAudioBeforeSend")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_RemoveNotifyAudioDevicesChanged=EOSSDK_real.EOS_RTCAudio_RemoveNotifyAudioDevicesChanged")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_RemoveNotifyAudioInputState=EOSSDK_real.EOS_RTCAudio_RemoveNotifyAudioInputState")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_RemoveNotifyAudioOutputState=EOSSDK_real.EOS_RTCAudio_RemoveNotifyAudioOutputState")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_RemoveNotifyParticipantUpdated=EOSSDK_real.EOS_RTCAudio_RemoveNotifyParticipantUpdated")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_SendAudio=EOSSDK_real.EOS_RTCAudio_SendAudio")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_SetAudioInputSettings=EOSSDK_real.EOS_RTCAudio_SetAudioInputSettings")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_SetAudioOutputSettings=EOSSDK_real.EOS_RTCAudio_SetAudioOutputSettings")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_SetInputDeviceSettings=EOSSDK_real.EOS_RTCAudio_SetInputDeviceSettings")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_SetOutputDeviceSettings=EOSSDK_real.EOS_RTCAudio_SetOutputDeviceSettings")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_SetPosition=EOSSDK_real.EOS_RTCAudio_SetPosition")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_UnregisterPlatformAudioUser=EOSSDK_real.EOS_RTCAudio_UnregisterPlatformAudioUser")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_UnregisterPlatformUser=EOSSDK_real.EOS_RTCAudio_UnregisterPlatformUser")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_UpdateParticipantVolume=EOSSDK_real.EOS_RTCAudio_UpdateParticipantVolume")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_UpdateReceiving=EOSSDK_real.EOS_RTCAudio_UpdateReceiving")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_UpdateReceivingVolume=EOSSDK_real.EOS_RTCAudio_UpdateReceivingVolume")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_UpdateSending=EOSSDK_real.EOS_RTCAudio_UpdateSending")
#pragma comment(linker, "/EXPORT:EOS_RTCAudio_UpdateSendingVolume=EOSSDK_real.EOS_RTCAudio_UpdateSendingVolume")
#pragma comment(linker, "/EXPORT:EOS_RTCData_AddNotifyDataReceived=EOSSDK_real.EOS_RTCData_AddNotifyDataReceived")
#pragma comment(linker, "/EXPORT:EOS_RTCData_AddNotifyParticipantUpdated=EOSSDK_real.EOS_RTCData_AddNotifyParticipantUpdated")
#pragma comment(linker, "/EXPORT:EOS_RTCData_RemoveNotifyDataReceived=EOSSDK_real.EOS_RTCData_RemoveNotifyDataReceived")
#pragma comment(linker, "/EXPORT:EOS_RTCData_RemoveNotifyParticipantUpdated=EOSSDK_real.EOS_RTCData_RemoveNotifyParticipantUpdated")
#pragma comment(linker, "/EXPORT:EOS_RTCData_SendData=EOSSDK_real.EOS_RTCData_SendData")
#pragma comment(linker, "/EXPORT:EOS_RTCData_UpdateReceiving=EOSSDK_real.EOS_RTCData_UpdateReceiving")
#pragma comment(linker, "/EXPORT:EOS_RTCData_UpdateSending=EOSSDK_real.EOS_RTCData_UpdateSending")
#pragma comment(linker, "/EXPORT:EOS_RTCVideo_AddNotifyParticipantUpdated=EOSSDK_real.EOS_RTCVideo_AddNotifyParticipantUpdated")
#pragma comment(linker, "/EXPORT:EOS_RTCVideo_AddNotifyVideoReceived=EOSSDK_real.EOS_RTCVideo_AddNotifyVideoReceived")
#pragma comment(linker, "/EXPORT:EOS_RTCVideo_CreateOutgoingVideoFrameFormat=EOSSDK_real.EOS_RTCVideo_CreateOutgoingVideoFrameFormat")
#pragma comment(linker, "/EXPORT:EOS_RTCVideo_RemoveNotifyParticipantUpdated=EOSSDK_real.EOS_RTCVideo_RemoveNotifyParticipantUpdated")
#pragma comment(linker, "/EXPORT:EOS_RTCVideo_RemoveNotifyVideoReceived=EOSSDK_real.EOS_RTCVideo_RemoveNotifyVideoReceived")
#pragma comment(linker, "/EXPORT:EOS_RTCVideo_SendVideo=EOSSDK_real.EOS_RTCVideo_SendVideo")
#pragma comment(linker, "/EXPORT:EOS_RTCVideo_SetAdaptVideoFrameCallback=EOSSDK_real.EOS_RTCVideo_SetAdaptVideoFrameCallback")
#pragma comment(linker, "/EXPORT:EOS_RTCVideo_SetVideoAllocationCallback=EOSSDK_real.EOS_RTCVideo_SetVideoAllocationCallback")
#pragma comment(linker, "/EXPORT:EOS_RTCVideo_SetVideoReleaseCallback=EOSSDK_real.EOS_RTCVideo_SetVideoReleaseCallback")
#pragma comment(linker, "/EXPORT:EOS_RTCVideo_UpdateReceiving=EOSSDK_real.EOS_RTCVideo_UpdateReceiving")
#pragma comment(linker, "/EXPORT:EOS_RTCVideo_UpdateSending=EOSSDK_real.EOS_RTCVideo_UpdateSending")
#pragma comment(linker, "/EXPORT:EOS_Sanctions_CopyPlayerSanctionByIndex=EOSSDK_real.EOS_Sanctions_CopyPlayerSanctionByIndex")
#pragma comment(linker, "/EXPORT:EOS_Sanctions_CreatePlayerSanctionAppeal=EOSSDK_real.EOS_Sanctions_CreatePlayerSanctionAppeal")
#pragma comment(linker, "/EXPORT:EOS_Sanctions_GetPlayerSanctionCount=EOSSDK_real.EOS_Sanctions_GetPlayerSanctionCount")
#pragma comment(linker, "/EXPORT:EOS_Sanctions_PlayerSanction_Release=EOSSDK_real.EOS_Sanctions_PlayerSanction_Release")
#pragma comment(linker, "/EXPORT:EOS_Sanctions_QueryActivePlayerSanctions=EOSSDK_real.EOS_Sanctions_QueryActivePlayerSanctions")
#pragma comment(linker, "/EXPORT:EOS_SessionDetails_Attribute_Release=EOSSDK_real.EOS_SessionDetails_Attribute_Release")
#pragma comment(linker, "/EXPORT:EOS_SessionDetails_CopyInfo=EOSSDK_real.EOS_SessionDetails_CopyInfo")
#pragma comment(linker, "/EXPORT:EOS_SessionDetails_CopySessionAttributeByIndex=EOSSDK_real.EOS_SessionDetails_CopySessionAttributeByIndex")
#pragma comment(linker, "/EXPORT:EOS_SessionDetails_CopySessionAttributeByKey=EOSSDK_real.EOS_SessionDetails_CopySessionAttributeByKey")
#pragma comment(linker, "/EXPORT:EOS_SessionDetails_GetSessionAttributeCount=EOSSDK_real.EOS_SessionDetails_GetSessionAttributeCount")
#pragma comment(linker, "/EXPORT:EOS_SessionDetails_Info_Release=EOSSDK_real.EOS_SessionDetails_Info_Release")
#pragma comment(linker, "/EXPORT:EOS_SessionDetails_Release=EOSSDK_real.EOS_SessionDetails_Release")
#pragma comment(linker, "/EXPORT:EOS_SessionModification_AddAttribute=EOSSDK_real.EOS_SessionModification_AddAttribute")
#pragma comment(linker, "/EXPORT:EOS_SessionModification_Release=EOSSDK_real.EOS_SessionModification_Release")
#pragma comment(linker, "/EXPORT:EOS_SessionModification_RemoveAttribute=EOSSDK_real.EOS_SessionModification_RemoveAttribute")
#pragma comment(linker, "/EXPORT:EOS_SessionModification_SetAllowedPlatformIds=EOSSDK_real.EOS_SessionModification_SetAllowedPlatformIds")
#pragma comment(linker, "/EXPORT:EOS_SessionModification_SetBucketId=EOSSDK_real.EOS_SessionModification_SetBucketId")
#pragma comment(linker, "/EXPORT:EOS_SessionModification_SetHostAddress=EOSSDK_real.EOS_SessionModification_SetHostAddress")
#pragma comment(linker, "/EXPORT:EOS_SessionModification_SetInvitesAllowed=EOSSDK_real.EOS_SessionModification_SetInvitesAllowed")
#pragma comment(linker, "/EXPORT:EOS_SessionModification_SetJoinInProgressAllowed=EOSSDK_real.EOS_SessionModification_SetJoinInProgressAllowed")
#pragma comment(linker, "/EXPORT:EOS_SessionModification_SetMaxPlayers=EOSSDK_real.EOS_SessionModification_SetMaxPlayers")
#pragma comment(linker, "/EXPORT:EOS_SessionModification_SetPermissionLevel=EOSSDK_real.EOS_SessionModification_SetPermissionLevel")
#pragma comment(linker, "/EXPORT:EOS_Sessions_AddNotifyJoinSessionAccepted=EOSSDK_real.EOS_Sessions_AddNotifyJoinSessionAccepted")
#pragma comment(linker, "/EXPORT:EOS_Sessions_AddNotifyLeaveSessionRequested=EOSSDK_real.EOS_Sessions_AddNotifyLeaveSessionRequested")
#pragma comment(linker, "/EXPORT:EOS_Sessions_AddNotifySendSessionNativeInviteRequested=EOSSDK_real.EOS_Sessions_AddNotifySendSessionNativeInviteRequested")
#pragma comment(linker, "/EXPORT:EOS_Sessions_AddNotifySessionInviteAccepted=EOSSDK_real.EOS_Sessions_AddNotifySessionInviteAccepted")
#pragma comment(linker, "/EXPORT:EOS_Sessions_AddNotifySessionInviteReceived=EOSSDK_real.EOS_Sessions_AddNotifySessionInviteReceived")
#pragma comment(linker, "/EXPORT:EOS_Sessions_AddNotifySessionInviteRejected=EOSSDK_real.EOS_Sessions_AddNotifySessionInviteRejected")
#pragma comment(linker, "/EXPORT:EOS_Sessions_CopyActiveSessionHandle=EOSSDK_real.EOS_Sessions_CopyActiveSessionHandle")
#pragma comment(linker, "/EXPORT:EOS_Sessions_CopySessionHandleByInviteId=EOSSDK_real.EOS_Sessions_CopySessionHandleByInviteId")
#pragma comment(linker, "/EXPORT:EOS_Sessions_CopySessionHandleByUiEventId=EOSSDK_real.EOS_Sessions_CopySessionHandleByUiEventId")
#pragma comment(linker, "/EXPORT:EOS_Sessions_CopySessionHandleForPresence=EOSSDK_real.EOS_Sessions_CopySessionHandleForPresence")
#pragma comment(linker, "/EXPORT:EOS_Sessions_CreateSessionModification=EOSSDK_real.EOS_Sessions_CreateSessionModification")
#pragma comment(linker, "/EXPORT:EOS_Sessions_CreateSessionSearch=EOSSDK_real.EOS_Sessions_CreateSessionSearch")
#pragma comment(linker, "/EXPORT:EOS_Sessions_DestroySession=EOSSDK_real.EOS_Sessions_DestroySession")
#pragma comment(linker, "/EXPORT:EOS_Sessions_DumpSessionState=EOSSDK_real.EOS_Sessions_DumpSessionState")
#pragma comment(linker, "/EXPORT:EOS_Sessions_EndSession=EOSSDK_real.EOS_Sessions_EndSession")
#pragma comment(linker, "/EXPORT:EOS_Sessions_GetInviteCount=EOSSDK_real.EOS_Sessions_GetInviteCount")
#pragma comment(linker, "/EXPORT:EOS_Sessions_GetInviteIdByIndex=EOSSDK_real.EOS_Sessions_GetInviteIdByIndex")
#pragma comment(linker, "/EXPORT:EOS_Sessions_IsUserInSession=EOSSDK_real.EOS_Sessions_IsUserInSession")
#pragma comment(linker, "/EXPORT:EOS_Sessions_JoinSession=EOSSDK_real.EOS_Sessions_JoinSession")
#pragma comment(linker, "/EXPORT:EOS_Sessions_QueryInvites=EOSSDK_real.EOS_Sessions_QueryInvites")
#pragma comment(linker, "/EXPORT:EOS_Sessions_RegisterPlayers=EOSSDK_real.EOS_Sessions_RegisterPlayers")
#pragma comment(linker, "/EXPORT:EOS_Sessions_RejectInvite=EOSSDK_real.EOS_Sessions_RejectInvite")
#pragma comment(linker, "/EXPORT:EOS_Sessions_RemoveNotifyJoinSessionAccepted=EOSSDK_real.EOS_Sessions_RemoveNotifyJoinSessionAccepted")
#pragma comment(linker, "/EXPORT:EOS_Sessions_RemoveNotifyLeaveSessionRequested=EOSSDK_real.EOS_Sessions_RemoveNotifyLeaveSessionRequested")
#pragma comment(linker, "/EXPORT:EOS_Sessions_RemoveNotifySendSessionNativeInviteRequested=EOSSDK_real.EOS_Sessions_RemoveNotifySendSessionNativeInviteRequested")
#pragma comment(linker, "/EXPORT:EOS_Sessions_RemoveNotifySessionInviteAccepted=EOSSDK_real.EOS_Sessions_RemoveNotifySessionInviteAccepted")
#pragma comment(linker, "/EXPORT:EOS_Sessions_RemoveNotifySessionInviteReceived=EOSSDK_real.EOS_Sessions_RemoveNotifySessionInviteReceived")
#pragma comment(linker, "/EXPORT:EOS_Sessions_RemoveNotifySessionInviteRejected=EOSSDK_real.EOS_Sessions_RemoveNotifySessionInviteRejected")
#pragma comment(linker, "/EXPORT:EOS_Sessions_SendInvite=EOSSDK_real.EOS_Sessions_SendInvite")
#pragma comment(linker, "/EXPORT:EOS_Sessions_StartSession=EOSSDK_real.EOS_Sessions_StartSession")
#pragma comment(linker, "/EXPORT:EOS_Sessions_UnregisterPlayers=EOSSDK_real.EOS_Sessions_UnregisterPlayers")
#pragma comment(linker, "/EXPORT:EOS_Sessions_UpdateSession=EOSSDK_real.EOS_Sessions_UpdateSession")
#pragma comment(linker, "/EXPORT:EOS_Sessions_UpdateSessionModification=EOSSDK_real.EOS_Sessions_UpdateSessionModification")
#pragma comment(linker, "/EXPORT:EOS_SessionSearch_CopySearchResultByIndex=EOSSDK_real.EOS_SessionSearch_CopySearchResultByIndex")
#pragma comment(linker, "/EXPORT:EOS_SessionSearch_Find=EOSSDK_real.EOS_SessionSearch_Find")
#pragma comment(linker, "/EXPORT:EOS_SessionSearch_GetSearchResultCount=EOSSDK_real.EOS_SessionSearch_GetSearchResultCount")
#pragma comment(linker, "/EXPORT:EOS_SessionSearch_Release=EOSSDK_real.EOS_SessionSearch_Release")
#pragma comment(linker, "/EXPORT:EOS_SessionSearch_RemoveParameter=EOSSDK_real.EOS_SessionSearch_RemoveParameter")
#pragma comment(linker, "/EXPORT:EOS_SessionSearch_SetMaxResults=EOSSDK_real.EOS_SessionSearch_SetMaxResults")
#pragma comment(linker, "/EXPORT:EOS_SessionSearch_SetParameter=EOSSDK_real.EOS_SessionSearch_SetParameter")
#pragma comment(linker, "/EXPORT:EOS_SessionSearch_SetSessionId=EOSSDK_real.EOS_SessionSearch_SetSessionId")
#pragma comment(linker, "/EXPORT:EOS_SessionSearch_SetTargetUserId=EOSSDK_real.EOS_SessionSearch_SetTargetUserId")
#pragma comment(linker, "/EXPORT:EOS_Shutdown=EOSSDK_real.EOS_Shutdown")
#pragma comment(linker, "/EXPORT:EOS_Stats_CopyStatByIndex=EOSSDK_real.EOS_Stats_CopyStatByIndex")
#pragma comment(linker, "/EXPORT:EOS_Stats_CopyStatByName=EOSSDK_real.EOS_Stats_CopyStatByName")
#pragma comment(linker, "/EXPORT:EOS_Stats_GetStatsCount=EOSSDK_real.EOS_Stats_GetStatsCount")
#pragma comment(linker, "/EXPORT:EOS_Stats_IngestStat=EOSSDK_real.EOS_Stats_IngestStat")
#pragma comment(linker, "/EXPORT:EOS_Stats_QueryStats=EOSSDK_real.EOS_Stats_QueryStats")
#pragma comment(linker, "/EXPORT:EOS_Stats_Stat_Release=EOSSDK_real.EOS_Stats_Stat_Release")
#pragma comment(linker, "/EXPORT:EOS_TitleStorage_CopyFileMetadataAtIndex=EOSSDK_real.EOS_TitleStorage_CopyFileMetadataAtIndex")
#pragma comment(linker, "/EXPORT:EOS_TitleStorage_CopyFileMetadataByFilename=EOSSDK_real.EOS_TitleStorage_CopyFileMetadataByFilename")
#pragma comment(linker, "/EXPORT:EOS_TitleStorage_DeleteCache=EOSSDK_real.EOS_TitleStorage_DeleteCache")
#pragma comment(linker, "/EXPORT:EOS_TitleStorage_FileMetadata_Release=EOSSDK_real.EOS_TitleStorage_FileMetadata_Release")
#pragma comment(linker, "/EXPORT:EOS_TitleStorage_GetFileMetadataCount=EOSSDK_real.EOS_TitleStorage_GetFileMetadataCount")
#pragma comment(linker, "/EXPORT:EOS_TitleStorage_QueryFile=EOSSDK_real.EOS_TitleStorage_QueryFile")
#pragma comment(linker, "/EXPORT:EOS_TitleStorage_QueryFileList=EOSSDK_real.EOS_TitleStorage_QueryFileList")
#pragma comment(linker, "/EXPORT:EOS_TitleStorage_ReadFile=EOSSDK_real.EOS_TitleStorage_ReadFile")
#pragma comment(linker, "/EXPORT:EOS_TitleStorageFileTransferRequest_CancelRequest=EOSSDK_real.EOS_TitleStorageFileTransferRequest_CancelRequest")
#pragma comment(linker, "/EXPORT:EOS_TitleStorageFileTransferRequest_GetFilename=EOSSDK_real.EOS_TitleStorageFileTransferRequest_GetFilename")
#pragma comment(linker, "/EXPORT:EOS_TitleStorageFileTransferRequest_GetFileRequestState=EOSSDK_real.EOS_TitleStorageFileTransferRequest_GetFileRequestState")
#pragma comment(linker, "/EXPORT:EOS_TitleStorageFileTransferRequest_Release=EOSSDK_real.EOS_TitleStorageFileTransferRequest_Release")
#pragma comment(linker, "/EXPORT:EOS_UI_AcknowledgeEventId=EOSSDK_real.EOS_UI_AcknowledgeEventId")
#pragma comment(linker, "/EXPORT:EOS_UI_AddNotifyDisplaySettingsUpdated=EOSSDK_real.EOS_UI_AddNotifyDisplaySettingsUpdated")
#pragma comment(linker, "/EXPORT:EOS_UI_AddNotifyMemoryMonitor=EOSSDK_real.EOS_UI_AddNotifyMemoryMonitor")
#pragma comment(linker, "/EXPORT:EOS_UI_GetFriendsExclusiveInput=EOSSDK_real.EOS_UI_GetFriendsExclusiveInput")
#pragma comment(linker, "/EXPORT:EOS_UI_GetFriendsVisible=EOSSDK_real.EOS_UI_GetFriendsVisible")
#pragma comment(linker, "/EXPORT:EOS_UI_GetNotificationLocationPreference=EOSSDK_real.EOS_UI_GetNotificationLocationPreference")
#pragma comment(linker, "/EXPORT:EOS_UI_GetToggleFriendsButton=EOSSDK_real.EOS_UI_GetToggleFriendsButton")
#pragma comment(linker, "/EXPORT:EOS_UI_GetToggleFriendsKey=EOSSDK_real.EOS_UI_GetToggleFriendsKey")
#pragma comment(linker, "/EXPORT:EOS_UI_HideFriends=EOSSDK_real.EOS_UI_HideFriends")
#pragma comment(linker, "/EXPORT:EOS_UI_IsSocialOverlayPaused=EOSSDK_real.EOS_UI_IsSocialOverlayPaused")
#pragma comment(linker, "/EXPORT:EOS_UI_IsValidButtonCombination=EOSSDK_real.EOS_UI_IsValidButtonCombination")
#pragma comment(linker, "/EXPORT:EOS_UI_IsValidKeyCombination=EOSSDK_real.EOS_UI_IsValidKeyCombination")
#pragma comment(linker, "/EXPORT:EOS_UI_PauseSocialOverlay=EOSSDK_real.EOS_UI_PauseSocialOverlay")
#pragma comment(linker, "/EXPORT:EOS_UI_PrePresent=EOSSDK_real.EOS_UI_PrePresent")
#pragma comment(linker, "/EXPORT:EOS_UI_RemoveNotifyDisplaySettingsUpdated=EOSSDK_real.EOS_UI_RemoveNotifyDisplaySettingsUpdated")
#pragma comment(linker, "/EXPORT:EOS_UI_RemoveNotifyMemoryMonitor=EOSSDK_real.EOS_UI_RemoveNotifyMemoryMonitor")
#pragma comment(linker, "/EXPORT:EOS_UI_ReportInputState=EOSSDK_real.EOS_UI_ReportInputState")
#pragma comment(linker, "/EXPORT:EOS_UI_SetDisplayPreference=EOSSDK_real.EOS_UI_SetDisplayPreference")
#pragma comment(linker, "/EXPORT:EOS_UI_SetToggleFriendsButton=EOSSDK_real.EOS_UI_SetToggleFriendsButton")
#pragma comment(linker, "/EXPORT:EOS_UI_SetToggleFriendsKey=EOSSDK_real.EOS_UI_SetToggleFriendsKey")
#pragma comment(linker, "/EXPORT:EOS_UI_ShowBlockPlayer=EOSSDK_real.EOS_UI_ShowBlockPlayer")
#pragma comment(linker, "/EXPORT:EOS_UI_ShowFriends=EOSSDK_real.EOS_UI_ShowFriends")
#pragma comment(linker, "/EXPORT:EOS_UI_ShowNativeProfile=EOSSDK_real.EOS_UI_ShowNativeProfile")
#pragma comment(linker, "/EXPORT:EOS_UI_ShowReportPlayer=EOSSDK_real.EOS_UI_ShowReportPlayer")
#pragma comment(linker, "/EXPORT:EOS_UserInfo_BestDisplayName_Release=EOSSDK_real.EOS_UserInfo_BestDisplayName_Release")
#pragma comment(linker, "/EXPORT:EOS_UserInfo_CopyBestDisplayName=EOSSDK_real.EOS_UserInfo_CopyBestDisplayName")
#pragma comment(linker, "/EXPORT:EOS_UserInfo_CopyBestDisplayNameWithPlatform=EOSSDK_real.EOS_UserInfo_CopyBestDisplayNameWithPlatform")
#pragma comment(linker, "/EXPORT:EOS_UserInfo_CopyExternalUserInfoByAccountId=EOSSDK_real.EOS_UserInfo_CopyExternalUserInfoByAccountId")
#pragma comment(linker, "/EXPORT:EOS_UserInfo_CopyExternalUserInfoByAccountType=EOSSDK_real.EOS_UserInfo_CopyExternalUserInfoByAccountType")
#pragma comment(linker, "/EXPORT:EOS_UserInfo_CopyExternalUserInfoByIndex=EOSSDK_real.EOS_UserInfo_CopyExternalUserInfoByIndex")
#pragma comment(linker, "/EXPORT:EOS_UserInfo_CopyUserInfo=EOSSDK_real.EOS_UserInfo_CopyUserInfo")
#pragma comment(linker, "/EXPORT:EOS_UserInfo_ExternalUserInfo_Release=EOSSDK_real.EOS_UserInfo_ExternalUserInfo_Release")
#pragma comment(linker, "/EXPORT:EOS_UserInfo_GetExternalUserInfoCount=EOSSDK_real.EOS_UserInfo_GetExternalUserInfoCount")
#pragma comment(linker, "/EXPORT:EOS_UserInfo_GetLocalPlatformType=EOSSDK_real.EOS_UserInfo_GetLocalPlatformType")
#pragma comment(linker, "/EXPORT:EOS_UserInfo_QueryUserInfo=EOSSDK_real.EOS_UserInfo_QueryUserInfo")
#pragma comment(linker, "/EXPORT:EOS_UserInfo_QueryUserInfoByDisplayName=EOSSDK_real.EOS_UserInfo_QueryUserInfoByDisplayName")
#pragma comment(linker, "/EXPORT:EOS_UserInfo_QueryUserInfoByExternalAccount=EOSSDK_real.EOS_UserInfo_QueryUserInfoByExternalAccount")
#pragma comment(linker, "/EXPORT:EOS_UserInfo_Release=EOSSDK_real.EOS_UserInfo_Release")

// ---- EAC stubs: return EOS_Success (0) without contacting any server ---
#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_AddExternalIntegrityCatalog(void) { return 0; }
// AddNotify functions must return a non-zero EOS_NotificationId (0 == EOS_INVALID_NOTIFICATIONID)
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_AddNotifyClientIntegrityViolated(void) { return 1; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_AddNotifyMessageToPeer(void) { return 1; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_AddNotifyMessageToServer(void) { return 1; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_AddNotifyPeerActionRequired(void) { return 1; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_AddNotifyPeerAuthStatusChanged(void) { return 1; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_BeginSession(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_EndSession(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_GetProtectMessageOutputLength(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_PollStatus(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_ProtectMessage(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_ReceiveMessageFromPeer(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_ReceiveMessageFromServer(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_RegisterPeer(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_RemoveNotifyClientIntegrityViolated(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_RemoveNotifyMessageToPeer(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_RemoveNotifyMessageToServer(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_RemoveNotifyPeerActionRequired(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_RemoveNotifyPeerAuthStatusChanged(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_Reserved01(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_UnprotectMessage(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatClient_UnregisterPeer(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_AddNotifyClientActionRequired(void) { return 1; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_AddNotifyClientAuthStatusChanged(void) { return 1; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_AddNotifyMessageToClient(void) { return 1; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_BeginSession(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_EndSession(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_GetProtectMessageOutputLength(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_LogEvent(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_LogGameRoundEnd(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_LogGameRoundStart(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_LogPlayerDespawn(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_LogPlayerRevive(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_LogPlayerSpawn(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_LogPlayerTakeDamage(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_LogPlayerTick(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_LogPlayerUseAbility(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_LogPlayerUseWeapon(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_ProtectMessage(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_ReceiveMessageFromClient(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_RegisterClient(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_RegisterEvent(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_RemoveNotifyClientActionRequired(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_RemoveNotifyClientAuthStatusChanged(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_RemoveNotifyMessageToClient(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_SetClientDetails(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_SetClientNetworkState(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_SetGameSessionId(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_UnprotectMessage(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_AntiCheatServer_UnregisterClient(void) { return 0; }
// ---- EOS_Platform_* stubs --------------------------------------------------
// EOS_Platform_Create: returns a non-null fake handle so the game doesn't crash
// on null, but NO real EOS platform is ever created -> no internal EAC threads.
static int g_fake_platform_handle = 0x50;
__declspec(dllexport) void* __cdecl EOS_Platform_Create(void) { return &g_fake_platform_handle; }
__declspec(dllexport) void  __cdecl EOS_Platform_Release(void) { }
__declspec(dllexport) void  __cdecl EOS_Platform_Tick(void) { }
__declspec(dllexport) int   __cdecl EOS_Platform_CheckForLauncherAndRestart(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Platform_GetApplicationStatus(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Platform_SetApplicationStatus(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Platform_GetNetworkStatus(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Platform_SetNetworkStatus(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Platform_GetActiveCountryCode(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Platform_GetActiveLocaleCode(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Platform_GetOverrideCountryCode(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Platform_SetOverrideCountryCode(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Platform_GetOverrideLocaleCode(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Platform_SetOverrideLocaleCode(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Platform_GetDesktopCrossplayStatus(void) { return 0; }
// All Get*Interface functions return null - safe because module functions (EOS_Auth_Login etc.)
// check for null handle and return EOS_InvalidParameters rather than crashing.
static int g_fake_anticheat_handle = 0xAC;
__declspec(dllexport) void* __cdecl EOS_Platform_GetAntiCheatClientInterface(void) { return &g_fake_anticheat_handle; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetAntiCheatServerInterface(void) { return &g_fake_anticheat_handle; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetAchievementsInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetAuthInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetConnectInterface(void) { return &g_fake_platform_handle; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetCustomInvitesInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetEcomInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetFriendsInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetIntegratedPlatformInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetKWSInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetLeaderboardsInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetLobbyInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetMetricsInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetModsInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetP2PInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetPlayerDataStorageInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetPresenceInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetProgressionSnapshotInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetReportsInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetRTCAdminInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetRTCInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetSanctionsInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetSessionsInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetStatsInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetTitleStorageInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetUIInterface(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Platform_GetUserInfoInterface(void) { return 0; }

// ---- EOS_Connect_* stubs ---------------------------------------------------
// AddNotify must return non-zero EOS_NotificationId
__declspec(dllexport) int   __cdecl EOS_Connect_AddNotifyAuthExpiration(void) { return 1; }
__declspec(dllexport) int   __cdecl EOS_Connect_AddNotifyLoginStatusChanged(void) { return 1; }
__declspec(dllexport) void  __cdecl EOS_Connect_RemoveNotifyAuthExpiration(void) { }
__declspec(dllexport) void  __cdecl EOS_Connect_RemoveNotifyLoginStatusChanged(void) { }
// Async ops: return EOS_Success (request accepted); callback never fires (Tick is no-op)
__declspec(dllexport) int   __cdecl EOS_Connect_Login(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Connect_CreateUser(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Connect_LinkAccount(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Connect_UnlinkAccount(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Connect_CreateDeviceId(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Connect_DeleteDeviceId(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Connect_TransferDeviceIdAccount(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Connect_QueryExternalAccountMappings(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Connect_QueryProductUserIdMappings(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Connect_VerifyIdToken(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Connect_Logout(void) { return 0; }
// Synchronous queries
__declspec(dllexport) int   __cdecl EOS_Connect_GetLoggedInUsersCount(void) { return 0; }
__declspec(dllexport) void* __cdecl EOS_Connect_GetLoggedInUserByIndex(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Connect_GetLoginStatus(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Connect_GetProductUserExternalAccountCount(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Connect_GetExternalAccountMapping(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Connect_GetProductUserIdMapping(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Connect_CopyIdToken(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Connect_CopyProductUserInfo(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Connect_CopyProductUserExternalAccountByIndex(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Connect_CopyProductUserExternalAccountByAccountId(void) { return 0; }
__declspec(dllexport) int   __cdecl EOS_Connect_CopyProductUserExternalAccountByAccountType(void) { return 0; }
__declspec(dllexport) void  __cdecl EOS_Connect_IdToken_Release(void) { }
__declspec(dllexport) void  __cdecl EOS_Connect_ExternalAccountInfo_Release(void) { }

#ifdef __cplusplus
} // extern "C"
#endif
