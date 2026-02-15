const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const Wallet = require('../models/Wallet.model');
const walletService = require('../services/walletService');

let mongoServer;

// Setup درایور حافظه MongoDB
beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  
  await mongoose.connect(mongoUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
});

// پاک کردن دیتابیس بعد از هر تست
afterEach(async () => {
  await Wallet.deleteMany({});
});

// قطع اتصال و توقف سرور
afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

describe('Wallet Model Tests', () => {
  test('should create a wallet successfully', async () => {
    const userId = new mongoose.Types.ObjectId();
    
    const wallet = await Wallet.create({
      user: userId,
      balance: 100000,
      lockedBalance: 20000
    });
    
    expect(wallet).toBeDefined();
    expect(wallet.balance).toBe(100000);
    expect(wallet.lockedBalance).toBe(20000);
    expect(wallet.isActive).toBe(true);
    expect(wallet.availableBalance).toBe(80000); // virtual field
  });
  
  test('should not allow negative balance', async () => {
    const userId = new mongoose.Types.ObjectId();
    
    await expect(
      Wallet.create({
        user: userId,
        balance: -1000
      })
    ).rejects.toThrow();
  });
  
  test('should not allow locked balance greater than total balance', async () => {
    const userId = new mongoose.Types.ObjectId();
    
    const wallet = new Wallet({
      user: userId,
      balance: 100000,
      lockedBalance: 150000
    });
    
    await expect(wallet.save()).rejects.toThrow();
  });
});

describe('Wallet Service Tests', () => {
  let testUserId;
  let testWalletId;
  
  beforeEach(async () => {
    testUserId = new mongoose.Types.ObjectId();
    
    const wallet = await Wallet.create({
      user: testUserId,
      balance: 100000,
      lockedBalance: 0
    });
    
    testWalletId = wallet._id;
  });
  
  test('should increase balance successfully', async () => {
    const result = await walletService.increaseBalance(
      testWalletId,
      50000,
      testUserId.toString()
    );
    
    expect(result.balance).toBe(150000);
    expect(result.dailyLimits.depositCount).toBe(1);
  });
  
  test('should decrease balance successfully', async () => {
    const result = await walletService.decreaseBalance(
      testWalletId,
      30000,
      testUserId.toString()
    );
    
    expect(result.balance).toBe(70000);
    expect(result.dailyLimits.withdrawalCount).toBe(1);
  });
  
  test('should throw error when insufficient balance', async () => {
    await expect(
      walletService.decreaseBalance(
        testWalletId,
        200000,
        testUserId.toString()
      )
    ).rejects.toThrow('موجودی کافی نیست');
  });
  
  test('should lock balance successfully', async () => {
    const result = await walletService.lockBalance(
      testWalletId,
      50000,
      testUserId.toString()
    );
    
    expect(result.lockedBalance).toBe(50000);
    expect(result.availableBalance).toBe(50000);
  });
  
  test('should unlock balance successfully', async () => {
    // اول قفل کن
    await walletService.lockBalance(
      testWalletId,
      50000,
      testUserId.toString()
    );
    
    // سپس آزاد کن
    const result = await walletService.unlockBalance(
      testWalletId,
      30000,
      testUserId.toString()
    );
    
    expect(result.lockedBalance).toBe(20000);
    expect(result.availableBalance).toBe(80000);
  });
});