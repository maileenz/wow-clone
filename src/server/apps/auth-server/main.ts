import { Server, ServerType } from "../server";
import { Singletons } from "../../../common/utilities/singletons";
import { sAuthSocketMgr } from "./server/auth-socket-mgr";
import { Socket } from "net";
import { env } from "../../../env";

class AuthServer extends Server {
  host = env.AUTH_SERVER_HOST;
  port = env.AUTH_SERVER_PORT;
  type = ServerType.Auth;
  protected onConnection(socket: Socket) {
    sAuthSocketMgr.HandleConnection(socket);
  }
}

export const sAuthServer = Singletons.create(AuthServer);
