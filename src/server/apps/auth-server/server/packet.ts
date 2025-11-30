export class Packet {
  // We keep the array-of-buffers approach; it is efficient for writing.
  private _parts: Buffer[] = [];

  constructor() {
    this._parts = [];
  }

  // Write 8-bit integer (1 byte)
  public uint8(value: number): this {
    const buf = Buffer.alloc(1);
    buf.writeUInt8(value, 0);
    this._parts.push(buf);
    return this; // Return this to allow chaining like: pkt.write().write()
  }

  // Write 16-bit integer (2 bytes)
  public uint16(value: number): this {
    const buf = Buffer.alloc(2);
    buf.writeUInt16LE(value, 0);
    this._parts.push(buf);
    return this;
  }

  // Write 32-bit integer (4 bytes)
  public uint32(value: number): this {
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(value, 0);
    this._parts.push(buf);
    return this;
  }

  // Write 64-bit integer (8 bytes) - ESSENTIAL for WoW Auth
  // Note: JavaScript numbers can't hold full 64-bit integers accurately,
  // so we use BigInt.
  public uint64(value: bigint | number): this {
    const buf = Buffer.alloc(8);
    // Convert number to BigInt if necessary
    const val = typeof value === "number" ? BigInt(value) : value;
    buf.writeBigUInt64LE(val, 0);
    this._parts.push(buf);
    return this;
  }

  // Alias for writeBuffer to match C++ syntax
  public append(buf: Buffer | Uint8Array): this {
    if (!Buffer.isBuffer(buf)) {
      this._parts.push(Buffer.from(buf));
    } else {
      this._parts.push(buf);
    }
    return this;
  }

  public string(str: string): this {
    this._parts.push(Buffer.from(str, "utf8"));
    // Note: WoW strings usually need a null terminator (0x00).
    // If you need C-Strings, uncomment the line below:
    // this._parts.push(Buffer.from([0x00]));
    return this;
  }

  // Correctly calculates total byte size
  public get length(): number {
    return this._parts.reduce((sum, part) => sum + part.length, 0);
  }

  public size() {
    return this._parts.length;
  }

  public toBuffer(): Buffer {
    return Buffer.concat(this._parts);
  }
}
