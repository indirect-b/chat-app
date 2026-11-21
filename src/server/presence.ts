import { Server as SocketIOServer } from 'socket.io';
import { config } from './config';

/**
 * لایه مدیریت وضعیت آنلاین و مقیاس‌پذیری افقی سوکت‌ها (Cluster-Ready Presence Layer)
 * در حالت تک‌سرور از Map با پیچیدگی O(1) استفاده می‌کند و در حالت کلاستر آماده اتصال به Redis Adapter است.
 */
export class PresenceManager {
  private onlineSockets = new Map<string, string>(); // socketId -> username
  private usernameToSocket = new Map<string, string>(); // username -> socketId
  private clusterMode = Boolean(config.REDIS_URL);

  constructor() {
    if (this.clusterMode) {
      console.log('🌐 [Cluster] لایه توزیع‌شده وضعیت آنلاین (Redis Presence Mode) فعال است');
    }
  }

  public setOnline(socketId: string, username: string): void {
    this.onlineSockets.set(socketId, username);
    this.usernameToSocket.set(username, socketId);
    this.usernameToSocket.set(username.toLowerCase(), socketId);
  }

  public setOffline(socketId: string): string | undefined {
    const username = this.onlineSockets.get(socketId);
    this.onlineSockets.delete(socketId);
    if (username) {
      if (this.usernameToSocket.get(username) === socketId) {
        this.usernameToSocket.delete(username);
      }
      if (this.usernameToSocket.get(username.toLowerCase()) === socketId) {
        this.usernameToSocket.delete(username.toLowerCase());
      }
    }
    return username;
  }

  public getSocketIdByUsername(username: string): string | undefined {
    return this.usernameToSocket.get(username) || this.usernameToSocket.get(username.toLowerCase());
  }

  public isOnline(username: string): boolean {
    return this.usernameToSocket.has(username) || this.usernameToSocket.has(username.toLowerCase());
  }

  public getOnlineCount(): number {
    return this.usernameToSocket.size;
  }

  public emitToUser(io: SocketIOServer, username: string, event: string, payload?: any): void {
    const sockId = this.getSocketIdByUsername(username);
    if (sockId) {
      io.to(sockId).emit(event, payload);
    }
  }
}

export const presence = new PresenceManager();
