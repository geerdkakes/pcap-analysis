
// log setup
const winston = require('winston');


module.exports = function(level)
{
  return winston.createLogger({
    level: level,
    format: winston.format.simple(),
    // defaultMeta: { service: 'user-service' },
    transports: [
      //
      // - Use console for logging
      //
      new winston.transports.Console()

    ]
  });
}

