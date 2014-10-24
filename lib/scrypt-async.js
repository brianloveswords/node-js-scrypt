var argScrubber = require('./argument-scrubber');
var scrypt_module_factory = require('./scrypt-module-factory');

module.exports = function scryptAsync(password, salt, options, callback) {
	var args = argScrubber.apply(null,arguments);
	var cb = args.callback || function(){}; //local ref to callback

	delete args.callback; //don't pass to child
	args.password = args.password.toString('base64');
	args.salt = args.salt.toString('base64');

	var start = new Date();

	try {
		var sm = scrypt_module_factory(args.options.maxmem);
		var pass = Array.prototype.slice.apply(new Buffer(args.password,'base64'));
		var salt = Array.prototype.slice.apply(new Buffer(args.salt, 'base64'));
		var hash = sm.crypto_scrypt(pass, salt, args.options.cost, args.options.blockSize, args.options.parallel, args.options.size);

		var ret = new Buffer(hash.length);
		for (var i=0; i<hash.length; i++) ret[i] = hash[i];
		return callback(null, ret);
	} catch(err) {
    return callback(err);
  }
};
