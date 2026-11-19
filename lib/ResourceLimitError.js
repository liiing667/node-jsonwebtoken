var JsonWebTokenError = require('./JsonWebTokenError');

var ResourceLimitError = function (message, limit, value) {
  JsonWebTokenError.call(this, message);
  this.name = 'ResourceLimitError';
  this.code = 'resource_limit';
  if (limit !== undefined) {
    this.limit = limit;
  }
  if (value !== undefined) {
    this.value = value;
  }
};

ResourceLimitError.prototype = Object.create(JsonWebTokenError.prototype);
ResourceLimitError.prototype.constructor = ResourceLimitError;

module.exports = ResourceLimitError;
