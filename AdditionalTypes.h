// These types are not part of ClientStructs, but help with reverse engineering.

enum Client::Game::Condition
{
  Condition_None,
  Condition_Normal,
  Condition_Dead,
  Condition_Emoting,
  Condition_Mounted,
  Condition_Crafting,
  Condition_Gathering,
  Condition_MeldingMateria,
  Condition_AnimLock,
  Condition_Carrying,
  Condition_RidingPillion,
  Condition_InThatPosition,
  Condition_ChocoboRacing,
  Condition_PlayingMiniGame,
  Condition_PlayingLordOfVerminion,
  Condition_ParticipatingInCustomMatch,
  Condition_Performing,
  Condition_Unknown17,
  Condition_Unknown18,
  Condition_Unknown19,
  Condition_Unknown20,
  Condition_Unknown21,
  Condition_Unknown22,
  Condition_Unknown23,
  Condition_Unknown24,
  Condition_Occupied,
  Condition_InCombat,
  Condition_Casting,
  Condition_SufferingStatusAffliction,
  Condition_SufferingStatusAffliction2,
  Condition_Occupied30,
  Condition_OccupiedInEvent,
  Condition_OccupiedInQuestEvent,
  Condition_Occupied33,
  Condition_BoundByDuty,
  Condition_OccupiedInCutSceneEvent,
  Condition_InDuelingArea,
  Condition_TradeOpen,
  Condition_Occupied38,
  Condition_Occupied39,
  Condition_ExecutingCraftingAction,
  Condition_PreparingToCraft,
  Condition_ExecutingGatheringAction,
  Condition_Fishing,
  Condition_Unknown44,
  Condition_BetweenAreas,
  Condition_Stealthed,
  Condition_Unknown47,
  Condition_Jumping,
  Condition_UsingChocoboTaxi,
  Condition_OccupiedSummoningBell,
  Condition_BetweenAreas51,
  Condition_SystemError,
  Condition_LoggingOut,
  Condition_ConditionLocation,
  Condition_WaitingForDuty,
  Condition_BoundByDuty56,
  Condition_MountOrOrnamentTransition,
  Condition_WatchingCutscene,
  Condition_WaitingForDutyFinder,
  Condition_CreatingCharacter,
  Condition_Jumping61,
  Condition_PvPDisplayActive,
  Condition_SufferingStatusAffliction63,
  Condition_Mounting,
  Condition_CarryingItem,
  Condition_UsingPartyFinder,
  Condition_UsingHousingFunctions,
  Condition_Transformed,
  Condition_OnFreeTrial,
  Condition_BeingMoved,
  Condition_Mounting71,
  Condition_SufferingStatusAffliction72,
  Condition_SufferingStatusAffliction73,
  Condition_RegisteringForRaceOrMatch,
  Condition_WaitingForRaceOrMatch,
  Condition_WaitingForTripleTriadMatch,
  Condition_InFlight,
  Condition_WatchingCutscene78,
  Condition_InDeepDungeon,
  Condition_Swimming,
  Condition_Diving,
  Condition_RegisteringForTripleTriadMatch,
  Condition_WaitingForTripleTriadMatch83,
  Condition_ParticipatingInCrossWorldPartyOrAlliance,
  Condition_Unknown85,
  Condition_DutyRecorderPlayback,
  Condition_Casting87,
  Condition_MountImmobile,
  Condition_InThisState89,
  Condition_RolePlaying,
  Condition_InDutyQueue,
  Condition_ReadyingVisitOtherWorld,
  Condition_WaitingToVisitOtherWorld,
  Condition_UsingFashionAccessory,
  Condition_BoundByDuty95,
  Condition_Unknown96,
  Condition_Disguised,
  Condition_RecruitingWorldOnly,
  Condition_Unknown99,
  Condition_EditingPortrait,
  Condition_Unknown101,
  Condition_PilotingMech,
  Condition_Unknown103,
  Condition_EditingStrategyBoard,
  Condition_Unknown105,
  Condition_Unknown106,
  Condition_Unknown107,
  Condition_Unknown108,
  Condition_Unknown109,
  Condition_Unknown110,
  Condition_Unknown111,
  Condition_MAX_CONDITION,
};

enum Client::Game::OnlineStatus : __int8
{
  OnlineStatus_Offline,
  OnlineStatus_GameQA,
  OnlineStatus_GameMaster,
  OnlineStatus_GameMasterBlue,
  OnlineStatus_EventParticipant,
  OnlineStatus_Disconnected,
  OnlineStatus_WaitingForFriendListApproval,
  OnlineStatus_WaitingForLinkshellApproval,
  OnlineStatus_WaitingForFreeCompanyApproval,
  OnlineStatus_NotFound,
  OnlineStatus_OfflineExd,
  OnlineStatus_BattleMentor,
  OnlineStatus_Busy,
  OnlineStatus_PvP,
  OnlineStatus_PlayingTripleTriad,
  OnlineStatus_ViewingCutscene,
  OnlineStatus_UsingAChocoboPorter,
  OnlineStatus_AwayFromKeyboard,
  OnlineStatus_CameraMode,
  OnlineStatus_LookingForRepairs,
  OnlineStatus_LookingToRepair,
  OnlineStatus_LookingToMeldMateria,
  OnlineStatus_RolePlaying,
  OnlineStatus_LookingForParty,
  OnlineStatus_SwordForHire,
  OnlineStatus_WaitingForDutyFinder,
  OnlineStatus_RecruitingPartyMembers,
  OnlineStatus_Mentor,
  OnlineStatus_PvEMentor,
  OnlineStatus_TradeMentor,
  OnlineStatus_PvPMentor,
  OnlineStatus_Returner,
  OnlineStatus_NewAdventurer,
  OnlineStatus_AllianceLeader,
  OnlineStatus_AlliancePartyLeader,
  OnlineStatus_AlliancePartyMember,
  OnlineStatus_PartyLeader,
  OnlineStatus_PartyMember,
  OnlineStatus_PartyLeaderCrossWorld,
  OnlineStatus_PartyMemberCrossWorld,
  OnlineStatus_AnotherWorld,
  OnlineStatus_SharingDuty,
  OnlineStatus_SimilarDuty,
  OnlineStatus_InDuty,
  OnlineStatus_TrialAdventurer,
  OnlineStatus_FreeCompany,
  OnlineStatus_GrandCompany,
  OnlineStatus_Online
};

struct Component::Exd::Sheets::Permission
{
  bool None;
  bool Normal;
  bool Dead;
  bool Emoting;
  bool Mounted;
  bool Crafting;
  bool Gathering;
  bool MeldingMateria;
  bool AnimLock;
  bool Carrying;
  bool RidingPillion;
  bool InThatPosition;
  bool ChocoboRacing;
  bool PlayingMiniGame;
  bool PlayingLordOfVerminion;
  bool ParticipatingInCustomMatch;
  bool Performing;
  bool Unknown17;
  bool Unknown18;
  bool Unknown19;
  bool Unknown20;
  bool Unknown21;
  bool Unknown22;
  bool Unknown23;
  bool Unknown24;
  bool Occupied;
  bool InCombat;
  bool Casting;
  bool SufferingStatusAffliction;
  bool SufferingStatusAffliction2;
  bool Occupied30;
  bool OccupiedInEvent;
  bool OccupiedInQuestEvent;
  bool Occupied33;
  bool BoundByDuty;
  bool OccupiedInCutSceneEvent;
  bool InDuelingArea;
  bool TradeOpen;
  bool Occupied38;
  bool Occupied39;
  bool ExecutingCraftingAction;
  bool PreparingToCraft;
  bool ExecutingGatheringAction;
  bool Fishing;
  bool Unknown44;
  bool BetweenAreas;
  bool Stealthed;
  bool Unknown47;
  bool Jumping;
  bool UsingChocoboTaxi;
  bool OccupiedSummoningBell;
  bool BetweenAreas51;
  bool SystemError;
  bool LoggingOut;
  bool ConditionLocation;
  bool WaitingForDuty;
  bool BoundByDuty56;
  bool MountOrOrnamentTransition;
  bool WatchingCutscene;
  bool WaitingForDutyFinder;
  bool CreatingCharacter;
  bool Jumping61;
  bool PvPDisplayActive;
  bool SufferingStatusAffliction63;
  bool Mounting;
  bool CarryingItem;
  bool UsingPartyFinder;
  bool UsingHousingFunctions;
  bool Transformed;
  bool OnFreeTrial;
  bool BeingMoved;
  bool Mounting71;
  bool SufferingStatusAffliction72;
  bool SufferingStatusAffliction73;
  bool RegisteringForRaceOrMatch;
  bool WaitingForRaceOrMatch;
  bool WaitingForTripleTriadMatch;
  bool InFlight;
  bool WatchingCutscene78;
  bool InDeepDungeon;
  bool Swimming;
  bool Diving;
  bool RegisteringForTripleTriadMatch;
  bool WaitingForTripleTriadMatch83;
  bool ParticipatingInCrossWorldPartyOrAlliance;
  bool Unknown85;
  bool DutyRecorderPlayback;
  bool Casting87;
  bool MountImmobile;
  bool InThisState89;
  bool RolePlaying;
  bool InDutyQueue;
  bool ReadyingVisitOtherWorld;
  bool WaitingToVisitOtherWorld;
  bool UsingFashionAccessory;
  bool BoundByDuty95;
  bool Unknown96;
  bool Disguised;
  bool RecruitingWorldOnly;
  bool Unknown99;
  bool EditingPortrait;
  bool Unknown101;
  bool PilotingMech;
  bool Unknown103;
  bool EditingStrategyBoard;
  bool Unknown105;
  bool Unknown106;
  bool Unknown107;
  bool Unknown108;
  bool Unknown109;
  bool Unknown110;
  bool Unknown111;
};
