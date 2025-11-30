import { Socket as NSocket } from "net";
import { Packet } from "./packet";
import { Opcodes } from "@/server/game/server/protocol/opcodes";
import { eAuthCmd } from "./auth-session";

export abstract class Socket<T extends Socket = any> {
  #started;
  #readBuffer: Buffer = Buffer.from([]);
  constructor(protected socket: NSocket, startEvents = true) {
    this.#started = false;
    if (startEvents) this.StartEvents();
  }
  public IsStarted() {
    return this.#started;
  }
  public StartEvents() {
    if (this.#started) return;
    this.#started = true;
    this.socket.on("data", this.#OnData.bind(this));
    this.socket.on("end", this.OnDisconnect.bind(this));
    this.socket.on("error", this.OnError.bind(this));
  }
  public StopEvents() {
    if (!this.#started) return;
    this.#started = false;
    this.socket.off("data", this.#OnData.bind(this));
    this.socket.off("end", this.OnDisconnect.bind(this));
    this.socket.off("error", this.OnError.bind(this));
  }
  #OnData(data: Buffer) {
    this.#readBuffer = data;
    this.OnOpcode(this.#readBuffer.readUInt8(0));
  }
  protected OnOpcode(_opcode: eAuthCmd | Opcodes): void {}
  protected OnDisconnect(): void {
    this.StopEvents();
  }
  protected OnError(error: Error): void {
    if (error.message.includes("ECONNRESET")) {
      console.warn(`[AUTH] Client connection reset: ${1}`);
    } else {
      console.error(`[AUTH] Socket error from ${1}:`, error.message);
    }
  }

  public GetSocket() {
    return this.socket;
  }
  public GetReadBuffer() {
    return this.#readBuffer;
  }
  public IsOpen() {
    return !this.socket.closed;
  }
  public GetRemoteAddress() {
    return `${this.GetRemoteIpAddress()}:${this.GetRemotePort()}`;
  }
  public GetRemoteIpAddress() {
    return this.socket.remoteAddress!;
  }
  public GetRemotePort() {
    return this.socket.remotePort!;
  }
  public SendPacket(packet: Packet) {
    if (this.socket.closed) return;
    if (packet.length) this.socket.write(packet.toBuffer());

    console.log("Packet length: ", packet.size());
  }
  public Close() {
    this.socket.end();
  }
}
