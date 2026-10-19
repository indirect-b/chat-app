export interface UserProfile {
  username: string;
  avatar: string | null;
  bio: string;
  status: 'online' | 'busy' | 'away' | string;
  public_key?: string | null;
}

export interface ContactItem {
  username: string;
  avatar: string | null;
  status: string;
  online?: boolean;
  public_key?: string | null;
}

export interface GroupItem {
  id: string;
  name: string;
  members: string[];
  created_at?: string;
}

export interface ChatMessage {
  id: string;
  room_id: string;
  sender: string;
  text: string;
  file_url: string | null;
  file_type: 'image' | 'voice' | 'file' | 'video' | null;
  reply_to_id: string | null;
  reply_to_text: string | null;
  reactions: Record<string, string[]>;
  is_edited: boolean;
  is_deleted: boolean;
  is_pinned: boolean;
  is_read: boolean;
  disappear_at: string | null;
  time: string;
  timestamp: number;
}

export interface RoomSummary {
  id: string;
  name: string;
  isGroup: boolean;
  avatar?: string | null;
  online?: boolean;
  preview?: string;
  time?: string;
  publicKey?: string | null;
}

export interface BlockedInfo {
  block_reason?: string;
  block_type?: 'permanent' | 'temporary' | string;
  block_until?: string;
}
