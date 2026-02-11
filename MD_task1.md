@include\AMManager\Client.hpp
adjust class arrage structure to inherit mode

AMClientInfoReader->AMClientOperator->AMClientPathOps

set memeber function DefaultPasswordCallback and DefaultDisconnectCallback as builtin value for password_cb_ and disconnect_cb_


wrapp class of include\AMManager\Client.hpp in namespace AMClientManage
rename AMClientInfoReader -> Reader

AMClientOperator -> Operator

AMClientPathOps -> PathOps

AMClientManager -> Manager

function in different classes implemented in different src files stored in src\manager\client
