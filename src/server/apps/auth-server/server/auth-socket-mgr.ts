import type { Socket } from "net";
import { AuthSession } from "./auth-session";
import { Singletons } from "../../../../common/utilities/singletons";
import { Logger } from "../../../../tools/logger";

class AuthSocketMgr {
  private sessions = new Map<Socket, AuthSession>();

  public GetSession(socket: Socket) {
    return this.sessions.get(socket);
  }

  public AddSession(socket: Socket) {
    socket.setNoDelay(true);
    const session = new AuthSession(socket);
    this.sessions.set(socket, session);
    Logger.info(`[AUTH] Client connected: ${session.GetRemoteAddress()}`);
  }

  public RemoveSession(socket: Socket) {
    this.sessions.delete(socket);
  }

  public Clear() {
    this.sessions.clear();
  }

  public HandleConnection(socket: Socket) {
    this.AddSession(socket);
  }
}

export const sAuthSocketMgr = Singletons.create(AuthSocketMgr);
