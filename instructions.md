@AMDataClass.hpp  
@AMBaseClient.hpp  
@AMFTPClient.hpp  
@AMSFTPClient.hpp  
@AMLocalClient.hpp  
@AMCore.hpp  

I want to abandon Python dependency and turn my project to pure cpp  
you have to conduct commands below  
1. remove all pybind11 include
2. exchange all python callback to cpp function
3. design a common-use callback wrapper to catch exception when callback errors
