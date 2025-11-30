import { WebSocket } from "uWebSockets.js";

export class WorldSession {
  public accountId: number = 0;
  public username: string = "";
  public sessionKey: Buffer | null = null;

  constructor(private ws: WebSocket<any>) {
    console.log("[Auth] New connection");
  }

  handleMessage(message: ArrayBuffer) {
    const buffer = Buffer.from(message);
    if (buffer.length < 1) return;

    const opcode = buffer.readUInt8(0);
  }

  send(buffer: Buffer) {
    this.ws.send(buffer, true, false);
  }

  close() {
    this.ws.close();
  }
}
