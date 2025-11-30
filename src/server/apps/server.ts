import { Logger } from "../../tools/logger";
import { type Socket, createServer } from "net";

type Host = `${number}.${number}.${number}.${number}`;

export enum ServerType {
  Auth = "Auth",
  World = "World",
}

export abstract class Server {
  private _netServer;
  abstract readonly host: Host;
  abstract readonly port: number;
  abstract readonly type: ServerType;

  constructor() {
    this._netServer = createServer(this.onConnection);
  }

  protected abstract onConnection(socket: Socket): void;

  public GetNetServer() {
    return this._netServer;
  }

  listen() {
    this._netServer.listen(this.port, this.host, () => {
      Logger.info(`[${this.type}] Server running on ${this.host}:${this.port}`);
    });

    // Handle server errors (e.g., port already in use)
    this._netServer.on("error", (err: any) => {
      if (err.code === "EADDRINUSE") {
        console.error(
          `[ERROR] Port ${this.port} is already in use. Please close the conflicting application.`
        );
      } else {
        console.error("[ERROR] Server failure:", err.message);
      }
      process.exit(1);
    });
  }

  private CloseServer() {
    return new Promise<void>((res) =>
      this._netServer.close((error) => {
        if (error) Logger.info(`[${this.type}] server is not open.`);
        res();
      })
    );
  }

  public async shutdown() {
    await this.CloseServer();
  }
}
