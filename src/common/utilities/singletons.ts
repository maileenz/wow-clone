/**
 * A utility class for creating and managing singleton instances of classes.
 * It ensures that only one instance of a registered class is ever created.
 */
export class Singletons {
  // A private static map to store the singletons.
  // The key is the class constructor (e.g., WorldMgr), and the value is its instance.
  private static singletons: Map<Function, any> = new Map();

  /**
   * Creates or retrieves the singleton instance of a given class.
   * * @param T The class type (e.g., WorldMgr).
   * @param C The constructor of the class (e.g., WorldMgr).
   * @returns The singleton instance of the class.
   */
  public static create<T>(C: new (...args: any[]) => T): T {
    // 1. Check if an instance of this class already exists
    if (Singletons.singletons.has(C)) {
      // If it exists, return the stored instance
      return Singletons.singletons.get(C) as T;
    }

    // 2. If it doesn't exist, create a new instance
    const instance = new C();

    // 3. Store the new instance in the map
    Singletons.singletons.set(C, instance);

    // 4. Return the new instance
    return instance;
  }

  public static clear() {
    this.singletons.clear();
  }
}
