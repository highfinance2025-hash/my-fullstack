// mongo-init.js
db.createUser({
    user: 'htland',
    pwd: 'htland_password',
    roles: [
      {
        role: 'readWrite',
        db: 'htland'
      }
    ]
  });
  
  db.createCollection('users');
  db.createCollection('wallets');
  db.createCollection('transactions');