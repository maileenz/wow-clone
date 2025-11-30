import { sAuthServer } from "./server/apps/auth-server/main";
import { sWorldServer } from "./server/apps/world-server/main";

sAuthServer.listen();
sWorldServer.listen();
