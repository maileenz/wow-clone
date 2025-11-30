// --- MOCK/PLACEHOLDER DEPENDENCIES ---
// These interfaces/objects represent functionality that would come from
// external libraries or core utilities in a real application (like AzerothCore's).

// Mock/Placeholder for Configuration Manager (sConfigMgr)
const sConfigMgr = {
  GetOption: <T>(key: string, defaultValue: T): T => {
    // In a real implementation, this would read from a config file (e.g., config.ini)
    if (key === "IPLocationFile") {
      // Replace this with the actual path to your IP database file for testing
      return "" as T;
    }
    return defaultValue;
  },
};

// Mock/Placeholder for Logging
const LOG = {
  INFO: (category: string, message: string, ...args: any[]) => {
    console.log(
      `[INFO] [${category}] ${message.replace(/{}/g, () => args.shift())}`
    );
  },
  ERROR: (category: string, message: string, ...args: any[]) => {
    console.error(
      `[ERROR] [${category}] ${message.replace(/{}/g, () => args.shift())}`
    );
  },
};

// Mock/Placeholder for Acore::StringTo<uint32> (Parsing string to 32-bit integer)
const Acore = {
  StringTo: {
    // Simple conversion, returns number or undefined if parsing fails
    // In a real scenario, this would check for overflow/validity more strictly
    uint32: (str: string): number | undefined => {
      const num = parseInt(str, 10);
      return isNaN(num) || num < 0 || num > 4294967295 ? undefined : num;
    },
  },
  // Mock for IP Address conversion utilities
  Net: {
    // Simplified mock: converts a string IP (e.g., "192.168.1.1") to a uint32 number
    // This is highly dependent on the target environment's IP utility library
    address_to_uint: (ip: number): number => ip, // Assuming make_address_v4 already returns the uint
    make_address_v4: (ipAddress: string): number => {
      const parts = ipAddress.split(".").map((p) => parseInt(p, 10));
      if (parts.length !== 4 || parts.some(isNaN)) return 0; // Invalid IP
      // 192.168.1.1 -> 192*2^24 + 168*2^16 + 1*2^8 + 1
      return parts[0] * 16777216 + parts[1] * 65536 + parts[2] * 256 + parts[3];
    },
  },
};

// Mock/Placeholder for ASSERT (Runtime check)
const ASSERT = (condition: boolean, message: string) => {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
};

// Use standard Node.js 'fs' for file operations
import * as fs from "fs";
import * as path from "path";
import { Singletons } from "./utilities/singletons";
import { Logger } from "../tools/logger";
import { env } from "../env";

// --- IP Location Data Structure ---

/**
 * @brief Represents a single range of IP addresses and the associated country information.
 */
export interface IpLocationRecord {
  /** The starting IP address in uint32 format. */
  IpFrom: number;
  /** The ending IP address in uint32 format. */
  IpTo: number;
  /** The 2-letter country code (e.g., "us"). */
  CountryCode: string;
  /** The full country name (e.g., "United States"). */
  CountryName: string;
}

// --- IpLocationStore Implementation (Singleton) ---

/**
 * @brief Singleton class for loading and querying the IP location database.
 */
export class IpLocationStore {
  // Stores the loaded IP location records.
  private _ipLocationStore: IpLocationRecord[] = [];

  /**
   * @brief Loads the IP location database from the configured file path.
   * @note This function implements the C++ file reading logic.
   */
  public Load(): void {
    this._ipLocationStore.length = 0;
    Logger.info("Loading IP Location Database...");

    const filePath = env.IPLocationFile;

    // 1. Check if file exists and is readable (C++ ifstream check)
    if (!fs.existsSync(filePath)) {
      LOG.ERROR(
        "server.loading",
        "IPLocation: No ip database file exists ({}).",
        filePath
      );
      return;
    }

    let fileContent: string;
    try {
      fileContent = fs.readFileSync(filePath, { encoding: "utf8" });
    } catch (e) {
      LOG.ERROR(
        "server.loading",
        "IPLocation: Ip database file ({}) can not be opened or read.",
        filePath
      );
      return;
    }

    // 2. Parse the CSV file content line by line
    const lines = fileContent.split("\n");
    for (let line of lines) {
      if (!line.trim()) continue;

      // Split the line by comma (assuming format: "ipFrom","ipTo","countryCode","countryName")
      // C++ uses getline with ',' as delimiter, which is close to CSV parsing.
      // A simple regex or custom split is used here to handle quoted fields.
      const parts =
        line.match(/(?:"[^"]*"|[^,]+)/g)?.map((p) => p.trim()) || [];

      if (parts.length !== 4) {
        // Skip malformed lines instead of breaking the entire loop
        continue;
      }

      let [ipFromStr, ipToStr, countryCode, countryName] = parts;

      // Remove quotation marks (C++: erase(std::remove(..., '"'), ...))
      const removeQuotes = (s: string) => s.replace(/"/g, "");
      ipFromStr = removeQuotes(ipFromStr);
      ipToStr = removeQuotes(ipToStr);
      countryCode = removeQuotes(countryCode);
      countryName = removeQuotes(countryName);

      // Remove newlines and carriage returns from the end (C++: countryName.erase(std::remove(..., '\r'/'\n'), ...))
      countryName = countryName.replace(/[\r\n]/g, "");

      // Convert country code to lowercase
      countryCode = countryCode.toLowerCase();

      // Convert IP strings to uint32 numbers (C++: Acore::StringTo<uint32>)
      const ipFrom = Acore.StringTo.uint32(ipFromStr);
      const ipTo = Acore.StringTo.uint32(ipToStr);

      if (ipFrom === undefined || ipTo === undefined) {
        continue; // Skip if conversion failed
      }

      // C++: _ipLocationStore.emplace_back(...)
      this._ipLocationStore.push({
        IpFrom: ipFrom,
        IpTo: ipTo,
        CountryCode: countryCode,
        CountryName: countryName,
      });
    }

    // 3. Sort the array by IpFrom (C++: std::sort)
    this._ipLocationStore.sort((a, b) => a.IpFrom - b.IpFrom);

    // 4. Assert non-overlapping ranges (C++: ASSERT(std::is_sorted(..., [](a,b){ return a.IpFrom < b.IpTo; })) )
    for (let i = 0; i < this._ipLocationStore.length - 1; i++) {
      const a = this._ipLocationStore[i];
      const b = this._ipLocationStore[i + 1];
      // If the end of range 'a' is greater than or equal to the start of range 'b', they overlap.
      // The C++ check `a.IpFrom < b.IpTo` is a bit unusual for checking non-overlap in a sorted array,
      // the standard check for non-overlap after sorting by IpFrom is `a.IpTo < b.IpFrom`.
      // The C++ assert actually checks a property related to sorting and overlap together.
      // We'll enforce the crucial non-overlap property:
      ASSERT(
        a.IpTo < b.IpFrom,
        "Overlapping IP ranges detected in database file."
      );
    }

    LOG.INFO(
      "server.loading",
      ">> Loaded {} ip location entries.",
      this._ipLocationStore.length
    );
    LOG.INFO("server.loading", " ");
  }

  /**
   * @brief Finds the location record for a given IP address string.
   * @param ipAddress The IP address string (e.g., "192.168.1.1").
   * @returns The matching IpLocationRecord or null if not found.
   */
  public GetLocationRecord(ipAddress: string): IpLocationRecord | null {
    // 1. Convert IP string to uint32 number
    const ipAsUint = Acore.Net.make_address_v4(ipAddress);
    const ip = Acore.Net.address_to_uint(ipAsUint);

    if (ip === 0) {
      // Handle invalid IP conversion
      return null;
    }

    // 2. Search using binary search (C++: std::upper_bound)
    // Find the *first* element in the array where `ip < loc.IpTo` is FALSE.
    // Wait, the C++ custom predicate is `return ip < loc.IpTo;`.
    // `std::upper_bound` finds the first element *greater* than `ip` using the custom comparator.
    // The comparator is: `loc is GREATER THAN ip` if `ip < loc.IpTo`.
    // This means it finds the first record `itr` where `ip < itr->IpTo` is true.

    let low = 0;
    let high = this._ipLocationStore.length;
    let foundIndex = -1;

    while (low < high) {
      const mid = Math.floor((low + high) / 2);
      const record = this._ipLocationStore[mid];

      // C++ predicate logic: ip < loc.IpTo
      if (ip < record.IpTo) {
        // If the IP is less than the current record's 'to' IP, this record is a *potential* match.
        // Keep searching in the lower half for a potentially better match (closer to start)
        foundIndex = mid;
        high = mid;
      } else {
        // If IP is >= record.IpTo, this record and all before it are too low.
        low = mid + 1;
      }
    }

    // 'foundIndex' now holds the index of the element found by upper_bound, or -1 if none.
    if (foundIndex === -1) {
      return null;
    }

    const itr = this._ipLocationStore[foundIndex];

    // 3. Final check: ensure the IP is actually within the range
    // C++: if (ip < itr->IpFrom) { return nullptr; }
    if (ip < itr.IpFrom) {
      return null;
    }

    // C++: return &(*itr);
    return itr;
  }
}

// Global accessor, equivalent to C++ #define sIPLocation IpLocationStore::instance()
export const sIPLocation = Singletons.create(IpLocationStore);
