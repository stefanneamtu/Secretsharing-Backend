const TimeLock = artifacts.require("TimeLock");

module.exports = function (deployer) {
  deployer.deploy(TimeLock);
};
