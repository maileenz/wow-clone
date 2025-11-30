export class ScriptMgr {
  static OnFailedEmailChange(id: number) {
    console.log(`Failed email change for account ${id}`);
  }
  static OnEmailChange(id: number) {
    console.log(`Email changed for account ${id}`);
  }
  static OnBeforeAccountDelete(id: number) {
    console.log(`About to delete account ${id}`);
  }
  static OnFailedPasswordChange(id: number) {
    console.log(`Failed password change for account ${id}`);
  }
  static OnPasswordChange(id: number) {
    console.log(`Password changed for account ${id}`);
  }
}
