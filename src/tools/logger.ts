import pino from "pino";
import pretty from "pino-pretty";

export class Logger {
  static #_instance?: pino.Logger;
  static #instance() {
    if (!this.#_instance) this.#_instance = pino(pretty());
    return this.#_instance;
  }
  public static info(...args: string[]) {
    this.#instance().info(args.join(" "));
  }
  public static warn(...args: string[]) {
    this.#instance().warn(args.join(" "));
  }
  public static error(...args: string[]) {
    this.#instance().error(args.join(" "));
  }
  public static debug(...args: string[]) {
    this.#instance().debug(args.join(" "));
  }
}
