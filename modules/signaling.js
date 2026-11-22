/**
 * Socket.IO signaling server – replaces ScaleDrone.
 *
 * Implements the same pub/sub semantics the meshcall client expects:
 *
 *   Client emits   join_room   { room, clientData }
 *   Client emits   leave_room  { room }
 *   Client emits   publish     { room, message }
 *
 *   Server emits   room_opened { room }
 *   Server emits   message     { room, data, id, timestamp, clientId }
 *   Server emits   members     { room, members }          (observable rooms, on join)
 *   Server emits   member_join { room, member }           (observable rooms)
 *   Server emits   member_leave{ room, member }           (observable rooms)
 *
 * "Observable" rooms are those whose name starts with "observable-".
 * They carry a live member list; every join/leave is announced to the room.
 *
 * Every published message is echoed back to the publisher (by joining the socket
 * into the Socket.IO room) so the client's liveness watchdog works as before.
 */
const crypto = require('crypto');

// phone → Set<socketId> — shared with the users router for /api/users/lookup
const onlinePhones = new Map();

function setupSignaling(httpServer, verifyToken) {
  const { Server } = require('socket.io');

  const io = new Server(httpServer, {
    cors: { origin: '*', methods: ['GET', 'POST'] },
    pingTimeout: 30_000,
    pingInterval: 20_000,
  });

  // observable rooms: roomName → Map<socketId, member>
  // member = { id: socketId, clientData: { deviceId, name, sessionId } }
  const observableMembers = new Map();

  // Authenticate every connection via the token passed in handshake auth.
  io.use((socket, next) => {
    const payload = verifyToken(socket.handshake.auth?.token);
    if (!payload) return next(new Error('unauthorized'));
    socket.user = payload;
    next();
  });

  io.on('connection', (socket) => {
    const joinedRooms = new Set();
    const phone = socket.user?.phone;
    if (phone) {
      if (!onlinePhones.has(phone)) onlinePhones.set(phone, new Set());
      onlinePhones.get(phone).add(socket.id);
    }

    socket.on('join_room', ({ room, clientData } = {}, ack) => {
      if (typeof room !== 'string' || !room) return;

      // If already in this room (reconnect path), leave first to reset member state.
      if (joinedRooms.has(room)) {
        cleanupObservable(room);
        socket.leave(room);
        joinedRooms.delete(room);
      }

      socket.join(room);
      joinedRooms.add(room);

      if (room.startsWith('observable-')) {
        if (!observableMembers.has(room)) observableMembers.set(room, new Map());
        const members = observableMembers.get(room);
        const member = { id: socket.id, clientData: clientData || {} };
        members.set(socket.id, member);
        // Tell existing members about the new arrival.
        socket.to(room).emit('member_join', { room, member });
        // Send the full member list to the new arrival.
        socket.emit('members', { room, members: [...members.values()] });
      }

      socket.emit('room_opened', { room });
      if (typeof ack === 'function') ack({ ok: true });
    });

    socket.on('leave_room', ({ room } = {}) => {
      if (typeof room !== 'string') return;
      cleanupObservable(room);
      socket.leave(room);
      joinedRooms.delete(room);
    });

    socket.on('publish', ({ room, message } = {}) => {
      if (typeof room !== 'string' || !message) return;
      const envelope = {
        data: message,
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        clientId: socket.id,
      };
      // Broadcast to everyone in the room including the sender (echo for liveness watchdog).
      io.to(room).emit('message', { room, ...envelope });
    });

    socket.on('disconnect', () => {
      for (const room of joinedRooms) cleanupObservable(room);
      joinedRooms.clear();
      if (phone) {
        const set = onlinePhones.get(phone);
        if (set) { set.delete(socket.id); if (set.size === 0) onlinePhones.delete(phone); }
      }
    });

    function cleanupObservable(room) {
      if (!observableMembers.has(room)) return;
      const members = observableMembers.get(room);
      const member = members.get(socket.id);
      if (!member) return;
      members.delete(socket.id);
      if (members.size === 0) observableMembers.delete(room);
      // Notify remaining members.
      socket.to(room).emit('member_leave', { room, member });
    }
  });

  return io;
}

module.exports = { setupSignaling, onlinePhones };
