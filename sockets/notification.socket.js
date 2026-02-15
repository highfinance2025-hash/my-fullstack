// sockets/notification.socket.js
const socketIO = require('socket.io');
const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');

class NotificationSocket {
  constructor(server) {
    this.io = socketIO(server, {
      cors: {
        origin: process.env.ALLOWED_ORIGINS.split(','),
        credentials: true
      },
      transports: ['websocket', 'polling'],
      pingTimeout: 60000,
      pingInterval: 25000
    });

    this.initialize();
  }

  initialize() {
    this.io.use(this.authenticate.bind(this));
    this.io.on('connection', this.handleConnection.bind(this));
  }

  async authenticate(socket, next) {
    try {
      const token = socket.handshake.auth.token;
      if (!token) {
        return next(new Error('Authentication error'));
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      socket.userId = decoded.userId;
      socket.join(`user:${decoded.userId}`);
      
      next();
    } catch (error) {
      next(new Error('Authentication error'));
    }
  }

  handleConnection(socket) {
    logger.info(`Socket connected: ${socket.id}`, { userId: socket.userId });

    socket.on('join-room', (room) => {
      socket.join(room);
      logger.debug(`Socket ${socket.id} joined room: ${room}`);
    });

    socket.on('disconnect', (reason) => {
      logger.info(`Socket disconnected: ${socket.id}`, { reason });
    });

    socket.on('error', (error) => {
      logger.error(`Socket error: ${socket.id}`, { error: error.message });
    });
  }

  sendToUser(userId, event, data) {
    this.io.to(`user:${userId}`).emit(event, {
      ...data,
      timestamp: new Date().toISOString()
    });
  }

  sendToRoom(room, event, data) {
    this.io.to(room).emit(event, {
      ...data,
      timestamp: new Date().toISOString()
    });
  }

  broadcast(event, data, excludeSocketId = null) {
    if (excludeSocketId) {
      socket.broadcast.emit(event, data);
    } else {
      this.io.emit(event, data);
    }
  }
}