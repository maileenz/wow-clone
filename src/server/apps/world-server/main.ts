import type { Socket } from "net";
import { Server, ServerType } from "../server";
import { Singletons } from "../../../common/utilities/singletons";
import { env } from "../../../env";

class WorldServer extends Server {
  host = env.WORLD_SERVER_HOST;
  port = env.WORLD_SERVER_PORT;
  type = ServerType.World;
  onConnection(socket: Socket): void {
    const remoteAddress = `${socket.remoteAddress}:${socket.remotePort}`;

    // --- Connection Event Logging ---
    console.log(`[${this.type}] Client connected: ${remoteAddress}`);

    // Set up event listener for data coming from the client
    socket.on("data", (data) => {
      // The first packet sent by the client is the SRP login attempt.
      // It contains the game version, username, and public key data.

      const decryptedHeader = data.subarray(0, 4);

      // 2. Read Packet Size and Opcode (Little Endian)
      const payloadSize = decryptedHeader.readUInt16LE(0); // Size of the remaining packet
      const opcode = decryptedHeader.readUInt16LE(2);

      console.log({ payloadSize, opcode });

      // Log the raw incoming packet data and assume it's a login attempt
      console.log(
        `\n[${this.type}] <<< Incoming Packet from ${remoteAddress} (Length: ${data.length} bytes)`,
        { data }
      );

      // In a real server, you would now parse this packet (SRP6 Handshake/Login Request)
      // For demonstration, we just log the action and the first few bytes.
      console.log(
        `[${
          this.type
        }] Login attempt detected. First 8 bytes (Opcode & Length): ${data
          .subarray(0, 8)
          .toString("hex")}`
      );

      // --- Login Attempt Logging ---
      // You would typically extract the username and console.log it here after parsing
      // console.log(`[AUTH] User '${extractedUsername}' is attempting to log in.`);

      // In a real server, you would:
      // 1. Parse the packet (e.g., using a custom buffer reader utility).
      // 2. Perform the SRP step 1 calculations.
      // 3. Send the SRP step 1 response (e.g., CMD_AUTH_LOGON_CHALLENGE).
      // 4. Handle subsequent packets (e.g., SRP step 2 / CMD_AUTH_LOGON_PROOF).
      // 5. Respond with a successful or failed login result.

      // For now, let's just send a simple, known invalid response to close the connection gracefully
      // The client will typically disconnect if it doesn't get a valid challenge response.
      // Sending a failure packet is complex, so we'll just log and close.
    });

    // --- Disconnection Event Logging ---
    socket.on("end", () => {
      console.log(`[${this.type}] Client disconnected: ${remoteAddress}`);
    });

    socket.on("error", (err) => {
      // Handle network errors (e.g., client forcefully closed the connection)
      if (err.message.includes("ECONNRESET")) {
        console.warn(
          `[${this.type}] Client connection reset: ${remoteAddress}`
        );
      } else {
        console.error(
          `[${this.type}] Socket error from ${remoteAddress}:`,
          err.message
        );
      }
    });
  }
}

export const sWorldServer = Singletons.create(WorldServer);

function getHeaderData(buffer: Buffer) {
  const header = buffer.subarray(0, 4);

  // 2. Read Packet Size and Opcode (Little Endian)
  const size = header.readUInt16LE(0); // Size of the remaining packet
  const opcode = header.readUInt16LE(2);

  return {
    size,
    opcode,
  };
}
