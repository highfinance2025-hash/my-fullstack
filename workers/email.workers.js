// workers/email.worker.js
const Bull = require('bull');
const nodemailer = require('nodemailer');
const logger = require('../utils/logger');

class EmailWorker {
  constructor() {
    this.queue = new Bull('email-queue', {
      redis: process.env.REDIS_URL,
      defaultJobOptions: {
        attempts: 3,
        backoff: {
          type: 'exponential',
          delay: 1000
        },
        removeOnComplete: true,
        removeOnFail: false
      }
    });

    this.setupProcessors();
    this.setupEvents();
  }

  setupProcessors() {
    // پردازش ایمیل‌های مختلف
    this.queue.process('welcome-email', 5, this.sendWelcomeEmail.bind(this));
    this.queue.process('order-confirmation', 10, this.sendOrderConfirmation.bind(this));
    this.queue.process('password-reset', 3, this.sendPasswordReset.bind(this));
  }

  setupEvents() {
    this.queue.on('completed', (job) => {
      logger.info(`Email job ${job.id} completed`, { type: job.name });
    });

    this.queue.on('failed', (job, err) => {
      logger.error(`Email job ${job.id} failed: ${err.message}`, { 
        job: job.data,
        attempts: job.attemptsMade 
      });
    });
  }

  async sendWelcomeEmail(job) {
    const { email, name } = job.data;
    
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: email,
      subject: 'خوش آمدید به HTLand',
      html: `<h1>سلام ${name}!</h1><p>به خانواده HTLand خوش آمدید...</p>`
    });
  }

  addJob(type, data, options = {}) {
    return this.queue.add(type, data, {
      priority: options.priority || 3,
      delay: options.delay || 0
    });
  }
}