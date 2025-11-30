export const MAX_NETCLIENT_PACKET_SIZE = 32767 - 1; // Client hardcap: int16 with trailing zero space otherwise crash on memory free

// TimeConstants
export const SECOND = 1;
export const MINUTE = SECOND * 60;
export const HOUR = MINUTE * 60;
export const DAY = HOUR * 24;
export const WEEK = DAY * 7;
export const MONTH = DAY * 30;
export const YEAR = MONTH * 12;
export const IN_MILLISECONDS = 1000;

export enum AccountTypes {
  SEC_PLAYER = 0,
  SEC_MODERATOR = 1,
  SEC_GAMEMASTER = 2,
  SEC_ADMINISTRATOR = 3,
  SEC_CONSOLE = 4, // must be always last in list, accounts must have less security level always also
}

export const MAX_ACCOUNT_FLAG = 32;
export enum AccountFlag {
  ACCOUNT_FLAG_GM = 0x1, // Account is GM
  ACCOUNT_FLAG_NOKICK = 0x2, // NYI UNK
  ACCOUNT_FLAG_COLLECTOR = 0x4, // NYI Collector's Edition
  ACCOUNT_FLAG_TRIAL = 0x8, // NYI Trial account
  ACCOUNT_FLAG_CANCELLED = 0x10, // NYI UNK
  ACCOUNT_FLAG_IGR = 0x20, // NYI Internet Game Room (Internet cafe?)
  ACCOUNT_FLAG_WHOLESALER = 0x40, // NYI UNK
  ACCOUNT_FLAG_PRIVILEGED = 0x80, // NYI UNK
  ACCOUNT_FLAG_EU_FORBID_ELV = 0x100, // NYI UNK
  ACCOUNT_FLAG_EU_FORBID_BILLING = 0x200, // NYI UNK
  ACCOUNT_FLAG_RESTRICTED = 0x400, // NYI UNK
  ACCOUNT_FLAG_REFERRAL = 0x800, // NYI Recruit-A-Friend, either referer or referee
  ACCOUNT_FLAG_BLIZZARD = 0x1000, // NYI UNK
  ACCOUNT_FLAG_RECURRING_BILLING = 0x2000, // NYI UNK
  ACCOUNT_FLAG_NOELECTUP = 0x4000, // NYI UNK
  ACCOUNT_FLAG_KR_CERTIFICATE = 0x8000, // NYI Korean certificate?
  ACCOUNT_FLAG_EXPANSION_COLLECTOR = 0x10000, // NYI TBC Collector's Edition
  ACCOUNT_FLAG_DISABLE_VOICE = 0x20000, // NYI Can't join voice chat
  ACCOUNT_FLAG_DISABLE_VOICE_SPEAK = 0x40000, // NYI Can't speak in voice chat
  ACCOUNT_FLAG_REFERRAL_RESURRECT = 0x80000, // NYI Scroll of Resurrection
  ACCOUNT_FLAG_EU_FORBID_CC = 0x100000, // NYI UNK
  ACCOUNT_FLAG_OPENBETA_DELL = 0x200000, // NYI https://wowpedia.fandom.com/wiki/Dell_XPS_M1730_World_of_Warcraft_Edition
  ACCOUNT_FLAG_PROPASS = 0x400000, // NYI UNK
  ACCOUNT_FLAG_PROPASS_LOCK = 0x800000, // NYI Pro pass (arena tournament)
  ACCOUNT_FLAG_PENDING_UPGRADE = 0x1000000, // NYI UNK
  ACCOUNT_FLAG_RETAIL_FROM_TRIAL = 0x2000000, // NYI UNK
  ACCOUNT_FLAG_EXPANSION2_COLLECTOR = 0x4000000, // NYI WotLK Collector's Edition
  ACCOUNT_FLAG_OVERMIND_LINKED = 0x8000000, // NYI Linked with Battle.net account
  ACCOUNT_FLAG_DEMOS = 0x10000000, // NYI UNK
  ACCOUNT_FLAG_DEATH_KNIGHT_OK = 0x20000000, // NYI Has level 55 on account?
  // Below might be StarCraft II related
  ACCOUNT_FLAG_S2_REQUIRE_IGR = 0x40000000, // NYI UNK
  ACCOUNT_FLAG_S2_TRIAL = 0x80000000, // NYI UNK
  // ACCOUNT_FLAG_S2_RESTRICTED        = 0xFFFFFFFF,  // NYI UNK
}

export enum LocaleConstant {
  LOCALE_enUS = 0,
  LOCALE_koKR = 1,
  LOCALE_frFR = 2,
  LOCALE_deDE = 3,
  LOCALE_zhCN = 4,
  LOCALE_zhTW = 5,
  LOCALE_esES = 6,
  LOCALE_esMX = 7,
  LOCALE_ruRU = 8,

  TOTAL_LOCALES,
}

export const DEFAULT_LOCALE = LocaleConstant.LOCALE_enUS;

export const MAX_LOCALES = 8;
export const MAX_ACCOUNT_TUTORIAL_VALUES = 8;
