const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 10000, // 10s timeout for Atlas
      socketTimeoutMS: 45000,
    });

    const isAtlas = conn.connection.host.includes('mongodb.net');
    const label   = isAtlas ? 'MongoDB ATLAS' : 'MongoDB LOCAL';

    console.log('\x1b[32m╔══════════════════════════════════════════════╗\x1b[0m');
    console.log(`\x1b[32m║  ${label} connected ✓                 ║\x1b[0m`);
    console.log(`\x1b[32m║  Host: ${conn.connection.host.substring(0,36).padEnd(36)}║\x1b[0m`);
    console.log(`\x1b[32m║  DB  : ${conn.connection.name.padEnd(36)}║\x1b[0m`);
    console.log('\x1b[32m╚══════════════════════════════════════════════╝\x1b[0m');

  } catch (error) {
    console.error('\x1b[31m╔══════════════════════════════════════════════╗\x1b[0m');
    console.error('\x1b[31m║  MongoDB CONNECTION FAILED ✗                 ║\x1b[0m');
    console.error(`\x1b[31m║  ${error.message.substring(0,44).padEnd(44)}║\x1b[0m`);
    console.error('\x1b[31m╠══════════════════════════════════════════════╣\x1b[0m');
    console.error('\x1b[31m║  Atlas fix:                                  ║\x1b[0m');
    console.error('\x1b[31m║  1. Check Atlas username & password in .env  ║\x1b[0m');
    console.error('\x1b[31m║  2. Whitelist your IP in Atlas Network Access║\x1b[0m');
    console.error('\x1b[31m║  3. Make sure cluster is not paused          ║\x1b[0m');
    console.error('\x1b[31m╚══════════════════════════════════════════════╝\x1b[0m');
    process.exit(1);
  }
};

module.exports = connectDB;
