import { Envelope } from './services/cryptoService';

export enum UserRole {
  ROOT = 'ROOT',
  MEMBER = 'MEMBER'
}

export interface Account {
  id: string;
  username: string;
  // No token here: the session is a HttpOnly cookie the page script cannot read.
}

export interface UserPermissions {
  viewTrueLevel?: boolean;
  /** May send announcements (root always can; granted from the Network tab). */
  announce?: boolean;
}

export interface User {
  id: string;
  accountId?: string;
  name: string;
  invitedBy: string | null;
  role: UserRole;
  level?: number;
  path?: string;
  inviteCode?: string;
  permissions?: UserPermissions;
  treeName?: string;
  treeNameVisible?: boolean; // root switch: show the network name to all members (separate from True Sight)
  monitorEnabled?: boolean; // root switch: whether the Monitor tab exists for this tree (default true)
  treeMode?: 'HIERARCHICAL' | 'DM' | 'HUB';
  // Direct-Only only: root switch. When on, any member may invite and every new
  // joiner is re-parented straight to the root (a flat referral star). On a
  // member's own node this mirrors the root's setting (so the client knows it
  // may show an invite QR); the authoritative value lives on the root.
  referralOpen?: boolean;
  /** Root switch (mirrored to all nodes): a network-wide channel any member can use. */
  globalChat?: boolean;
  /** Root switch (hierarchical + Direct-Only): auto-accept invite joins instead of
   *  queuing them for approval. Off by default. */
  autoAcceptInvites?: boolean;
  // Referral joins keep a pointer (internal id, server-side only) to the member
  // who actually shared the link, distinct from invitedBy (which is the root).
  referredBy?: string;
  // Invitee grouping (set BY this node, about its own direct invitees). The
  // inviter can partition its invitees into groups that cannot see or message
  // each other. Keyed by the invitee's node id. Absence = ungrouped.
  inviteeGroups?: Record<string, string | string[]>;   // childNodeId -> groupId, or an array of group ids for a member in several groups
  groupLabels?: Record<string, string>;      // groupId -> display label
  groupParents?: Record<string, string>;     // groupId -> parent groupId (nested groups)
  groupLinks?: Record<string, { groups?: string[]; name: string; archived?: boolean; refs?: { o: string; g: string }[]; crossLevel?: boolean }>; // linkId -> linked group ids (cross-group chat); cross-level links use refs {ownerPublicId, groupId}
  groupVisitors?: Record<string, string[]>; // (owner/oversight view) gid -> public ids of cross-level VISITORS added to that group
  visiting?: { o: string; g: string; name: string; ownerName?: string; members?: string[] }[]; // (on ME) groups on other branches I'm a cross-level visitor of, with that group's member public ids
  myGroupUnder?: string | string[]; // the group id(s) I'm in under my inviter (my own membership only)
  myGroupName?: string; // the display name of the (first) group I'm in under my inviter
  myGroupNames?: string[]; // when I'm in several groups under my inviter, all their names
  myLinks?: Record<string, { name: string; archived?: boolean }>; // (on inviter's record) links my group takes part in
  crossLinks?: Record<string, { name: string; archived?: boolean }>; // (on ME, from tree-context) cross-level channels I take part in
  provisionName?: string;
  relativeLevel?: number;
  color: string;
  // Network Profile (per-node, same visibility tier as name/color). The avatar
  // BYTES load lazily from the server keyed by avatarAt; only this version marker
  // rides in the tree/context payload. bio + nameHistory are fetched on demand for
  // the profile info view.
  avatarAt?: number;        // >0 when this node has a profile photo (cache-bust key)
  bio?: string;             // only populated on the info view (not in tree context)
  nameHistory?: { name: string; at: number }[]; // prior display names, oldest→newest
  isDescendant?: boolean;
  isAncestor?: boolean;
  isMe?: boolean;
  encPub?: JsonWebKey;
  sigPub?: JsonWebKey;
  wrappedKeys?: string;
  // TOFU pin reconciliation result for this contact's keys (set client-side):
  keyStatus?: 'new' | 'match' | 'changed';
  pending?: boolean; // join request awaiting the inviter's approval
  /** Personal hubs only: which side of a pending contact edge asked ('out' = I did). */
  pendingDirection?: 'in' | 'out';
  /** Another visible member has a look-alike name (V8 L-8; computed client-side). */
  nameClash?: boolean;
  // ---- V8 phase 2: signed membership + end-to-end encrypted profiles ----
  /** Signal identity key as the SERVER reports it (trusted only where a signed
   *  membership certificate agrees). */
  ik?: string;
  /** Encrypted profile (name, bio, name history, photo key) — decrypted client-side. */
  profileCt?: string;
  profileAt?: number;
  /** (on ME) own name + network name under the account key, for the picker. */
  selfCt?: string;
  /** (on ME) pinned network-root identity, under the account key. */
  anchorCt?: string;
  /** (on ME / picker) public id of this node's network root. */
  treeRoot?: string;
  /** Encrypted network name (on the root's entry). */
  treeNameCt?: string;
  /** (root only) the server reports a member left; the app rotates the network key. */
  rotateNeeded?: boolean;
  /** Client-side: a signed certificate chain from the pinned root vouches for this
   *  node AND its identity key. */
  memberVerified?: boolean;
  /** Client-side: the profile's owner signature checked out. */
  profileSigned?: boolean;
  /** Client-side: plaintext profile from before end-to-end encryption (owner hasn't updated yet). */
  legacyProfile?: boolean;
  /** Client-side: profile present but this device has no key for it yet. */
  profileLocked?: boolean;
}

/** Pointer to an out-of-band encrypted media blob (Signal-style). The bytes
 *  live in the attachments table on the server as opaque ciphertext; this
 *  pointer (id + key + iv + mime) rides inside the E2E-encrypted message, so
 *  the server never sees the key. Recipients fetch + decrypt lazily. */
export interface AttachmentRef {
  id: string;                 // server blob id
  key: string;                // base64 AES-GCM key (E2E; never leaves ciphertext)
  iv: string;                 // base64 IV
  mime: string;               // sanitized MIME (e.g. image/jpeg)
  kind: 'image' | 'audio' | 'video';
  name?: string;
  peaks?: number[];           // voice notes: amplitude envelope (0..1) captured while recording, so the sent bubble always shows the real waveform
  durMs?: number;             // voice notes: true recording length in ms (MediaRecorder blobs report a wrong/Infinity duration, so we trust this)
}

export interface Message {
  id: string;
  senderId: string;
  // Decrypted on the client after envelope decryption (never sent in clear):
  text?: string;
  imageUrl?: string;
  audioUrl?: string;
  videoUrl?: string;
  attachments?: AttachmentRef[];
  timestamp: number;
  expiresAt?: number;
  type: 'BROADCAST' | 'PEER' | 'GLOBAL';
  targetCircle?: 'UP' | 'DOWN';
  /** For 1:1 sends (DM / personal hub): the contact this message was sent to. */
  peerId?: string;
  /** For inviter descendants group chats: which group this message belongs to. */
  targetGroup?: string;
  targetBranchId?: string;
  depthLimit?: number;
  envelope?: Envelope;
  verified?: boolean;    // content bound to the sender's ratchet slot (V8 H-1) AND sender identity unchanged
  keyChanged?: boolean;  // sender's key differs from what we pinned (possible MITM)
  /** v71: every check except the key-change one passed at ingest (content bound +
   *  verified member) — what `verified` becomes if the user re-trusts the new key. */
  verifiedIfKeyOk?: boolean;
  /** v71 M1: an edit that was NOT applied (its sender's key changed, or it wasn't
   *  content-bound); the attempted text is shown as its own flagged message. */
  editRefused?: boolean;
  /** Sender's own copy only: exactly who this message was encrypted to (monitors
   *  included) — shown in Message Info so the audience is auditable (V8 H-2). */
  sentTo?: { id: string; name: string; verified?: boolean }[];
  /** Sender's own copy only: recipients the server listed that this app REFUSED to
   *  encrypt to because their membership couldn't be verified (V8 phase 2, H-2). */
  withheld?: number;
  /** Sender's own copy only (v72 B3): recipients left out because their security key
   *  changed and hasn't been re-trusted. */
  keyChangedWithheld?: number;
  readAt?: number; // set locally when a read receipt for this message arrives
  /** Local-only, transient: an optimistic bubble still in flight (not yet confirmed
   *  stored by the server). Cleared when the send echoes back. Drives the per-message
   *  status: sending (clock) → delivered (single check) → read (double check). */
  sending?: boolean;
  /** Quoted message. v71 L7: when this device holds the quoted message, name and
   *  text come from its own copy; otherwise the quote is the sender's claim and is
   *  shown marked `unverified`. */
  replyTo?: { mid: string; name: string; text: string; unverified?: boolean };
  senderLevel?: number; // BROADCAST only: announcer's level at send time (root = 0)
  edited?: boolean; // text was replaced by a later edit
  editedAt?: number;
  ackRequested?: boolean;   // sender asked recipients to acknowledge
  acks?: { id: string; name: string; ts: number }[]; // who acknowledged (sender view)
  reactions?: Record<string, { id: string; name: string }[]>; // emoji -> reactors
  /** Local-only system entry: a record of a voice/video call in this chat. */
  callLog?: {
    direction: 'outgoing' | 'incoming';
    outcome: 'completed' | 'missed' | 'declined' | 'no_answer';
    durationSec?: number; // present when completed
    video?: boolean;
    callerName?: string;                    // who started the call
    participants?: { name: string }[];      // everyone who joined
  };
}

export interface Invite {
  code: string;
  inviterId: string;
  isUsed: boolean;
  recipientName?: string | null;
  expiresAt?: number;
  permanent?: boolean;
}

export interface JoinRequest {
  id: string;
  name: string;
  requestedAt: number;
  /** Referral joins: the name of the member who shared the link (root approves). */
  referredByName?: string;
  /** Group ("branch") joins: the name of the group they used a link to join. */
  branchName?: string;
  /** v72 B2: how the requester's key was verified — 'link' (their invite link bound
   *  it), 'network' (their membership in a network you share vouched for it), or
   *  null (unverified: the request can't be accepted). */
  verified?: 'link' | 'network' | null;
}

export interface AppState {
  account: Account | null;
  currentUser: User | null;
  users: User[];
  messages: Message[];
  invites: Invite[];
  isLoading: boolean;
  joinRequests?: JoinRequest[];
  acks?: Record<string, { id: string; name: string; ts: number }[]>;
  reactions?: Record<string, Record<string, { id: string; name: string }[]>>; // mid -> emoji -> reactors
}
