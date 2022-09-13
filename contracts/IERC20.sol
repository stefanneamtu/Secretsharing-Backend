// Adapted from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md

// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

// Interface to create an ERC20 token
interface IERC20 {
    function totalSupply() external view returns (uint256);

    function balanceOf(address _owner) external view returns (uint256);

    function transfer(address _recipient, uint256 _amount)
        external
        returns (bool);

    function allowance(address _owner, address _spender)
        external
        view
        returns (uint256);

    function approve(address _spender, uint256 _amount) external returns (bool);

    function transferFrom(
        address _sender,
        address _recipient,
        uint256 _amount
    ) external returns (bool);

    function name() external view returns (string memory);

    function symbol() external view returns (string memory);

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(
        address indexed _owner,
        address indexed _spender,
        uint256 _value
    );
}
