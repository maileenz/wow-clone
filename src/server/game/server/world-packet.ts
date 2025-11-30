import { Opcodes } from "./protocol/opcodes";
import ByteBuffer from "bytebuffer";

export class WorldPacket extends ByteBuffer {
  protected m_opcode: Opcodes = Opcodes.NULL_OPCODE;
  protected m_receivedTime: number = 0;

  constructor();
  constructor(opcode: Opcodes, res?: number);
  constructor(packet: WorldPacket);
  constructor(packet: WorldPacket, receivedTime: number);
  constructor(arg1?: any, arg2?: any) {
    if (typeof arg1 === "undefined") super(0);
    else if (
      typeof arg1 === "number" &&
      (typeof arg2 === "undefined" || typeof arg2 == "number")
    ) {
      super(arg2 ?? 200);
      this.m_opcode = arg1;
    } else if (arg1 satisfies WorldPacket) {
      super(arg1.capacity());
      this.m_opcode = arg1.m_opcode;
      if (typeof arg2 === "number") this.m_receivedTime = arg2;
    }
  }

  Initialize(opcode: Opcodes, newRes = 200) {
    this.clear();
    this.resize(newRes);
    this.m_opcode = opcode;
  }

  GetOpcode() {
    return this.m_opcode;
  }

  SetOpcode(opcode: Opcodes) {
    this.m_opcode = opcode;
  }
}
