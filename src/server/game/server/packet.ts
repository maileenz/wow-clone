import { WorldPacket } from "./world-packet";

export class Packet {
  constructor(protected _worldPacket: WorldPacket) {}
  Write() {
    return this._worldPacket;
  }
  Read() {}
  GetRawPacket() {
    return this._worldPacket;
  }
  GetSize() {
    return this._worldPacket.capacity();
  }
}

export class ServerPacket extends Packet {}
