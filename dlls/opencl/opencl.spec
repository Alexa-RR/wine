<<<<<<< HEAD
# OpenCL 1.0
@ stdcall clGetPlatformIDs( long ptr ptr ) wine_clGetPlatformIDs
@ stdcall clGetPlatformInfo( long long long ptr ptr ) wine_clGetPlatformInfo

@ stdcall clGetDeviceIDs( long long long ptr ptr ) wine_clGetDeviceIDs
@ stdcall clGetDeviceInfo( long long long ptr ptr ) wine_clGetDeviceInfo

@ stdcall clCreateContext(ptr long ptr ptr ptr ptr) wine_clCreateContext
@ stdcall clCreateContextFromType(ptr long ptr ptr ptr) wine_clCreateContextFromType
@ stdcall clRetainContext( long ) wine_clRetainContext
@ stdcall clReleaseContext( long ) wine_clReleaseContext
@ stdcall clGetContextInfo( long long long ptr ptr ) wine_clGetContextInfo

@ stdcall clCreateCommandQueue( long long long ptr ) wine_clCreateCommandQueue
@ stdcall clRetainCommandQueue( long ) wine_clRetainCommandQueue
@ stdcall clReleaseCommandQueue( long ) wine_clReleaseCommandQueue
@ stdcall clGetCommandQueueInfo( long long long ptr ptr ) wine_clGetCommandQueueInfo
@ stdcall clSetCommandQueueProperty( long long long ptr ) wine_clSetCommandQueueProperty

@ stdcall clCreateBuffer( long long long ptr ptr ) wine_clCreateBuffer
@ stdcall clCreateImage2D( long long ptr long long long ptr ptr ) wine_clCreateImage2D
@ stdcall clCreateImage3D( long long ptr long long long long long ptr ptr ) wine_clCreateImage3D
@ stdcall clRetainMemObject( long ) wine_clRetainMemObject
@ stdcall clReleaseMemObject( long ) wine_clReleaseMemObject
@ stdcall clGetSupportedImageFormats( long long long long ptr ptr ) wine_clGetSupportedImageFormats
@ stdcall clGetMemObjectInfo( long long long ptr ptr ) wine_clGetMemObjectInfo
@ stdcall clGetImageInfo( long long long ptr ptr ) wine_clGetImageInfo

@ stdcall clCreateSampler( long long long long ptr ) wine_clCreateSampler
@ stdcall clRetainSampler( long ) wine_clRetainSampler
@ stdcall clReleaseSampler( long ) wine_clReleaseSampler
@ stdcall clGetSamplerInfo( long long long ptr ptr ) wine_clGetSamplerInfo

@ stdcall clCreateProgramWithSource( long long ptr ptr ptr ) wine_clCreateProgramWithSource
@ stdcall clCreateProgramWithBinary( long long ptr ptr ptr ptr ptr ) wine_clCreateProgramWithBinary
@ stdcall clRetainProgram( long ) wine_clRetainProgram
@ stdcall clReleaseProgram( long ) wine_clReleaseProgram
@ stdcall clBuildProgram( long long ptr str ptr ptr ) wine_clBuildProgram
@ stdcall clUnloadCompiler() wine_clUnloadCompiler
@ stdcall clGetProgramInfo( long long long ptr ptr ) wine_clGetProgramInfo
@ stdcall clGetProgramBuildInfo( long long long long ptr ptr ) wine_clGetProgramBuildInfo

@ stdcall clCreateKernel( long str ptr ) wine_clCreateKernel
@ stdcall clCreateKernelsInProgram( long long ptr ptr ) wine_clCreateKernelsInProgram
@ stdcall clRetainKernel( long ) wine_clRetainKernel
@ stdcall clReleaseKernel( long ) wine_clReleaseKernel
@ stdcall clSetKernelArg( long long long ptr ) wine_clSetKernelArg
@ stdcall clGetKernelInfo( long long long ptr ptr ) wine_clGetKernelInfo
@ stdcall clGetKernelWorkGroupInfo( long long long long ptr ptr ) wine_clGetKernelWorkGroupInfo

@ stdcall clWaitForEvents( long ptr ) wine_clWaitForEvents
@ stdcall clGetEventInfo( long long long ptr ptr ) wine_clGetEventInfo
@ stdcall clReleaseEvent( long ) wine_clReleaseEvent
@ stdcall clRetainEvent( long ) wine_clRetainEvent

@ stdcall clGetEventProfilingInfo( long long long ptr ptr ) wine_clGetEventProfilingInfo

@ stdcall clFlush( long ) wine_clFlush
@ stdcall clFinish( long ) wine_clFinish

@ stdcall clEnqueueReadBuffer( long long long long long ptr long ptr ptr ) wine_clEnqueueReadBuffer
@ stdcall clEnqueueWriteBuffer( long long long long long ptr long ptr ptr ) wine_clEnqueueWriteBuffer
@ stdcall clEnqueueCopyBuffer( long long long long long long long ptr ptr ) wine_clEnqueueCopyBuffer
@ stdcall clEnqueueReadImage( long long long ptr ptr long long ptr long ptr ptr ) wine_clEnqueueReadImage
@ stdcall clEnqueueWriteImage( long long long ptr ptr long long ptr long ptr ptr ) wine_clEnqueueWriteImage
@ stdcall clEnqueueCopyImage( long long long ptr ptr ptr long ptr ptr ) wine_clEnqueueCopyImage
@ stdcall clEnqueueCopyImageToBuffer( long long long ptr ptr long long ptr ptr ) wine_clEnqueueCopyImageToBuffer
@ stdcall clEnqueueCopyBufferToImage( long long long long ptr ptr long ptr ptr ) wine_clEnqueueCopyBufferToImage
@ stdcall clEnqueueMapBuffer( long long long long long long long ptr ptr ptr ) wine_clEnqueueMapBuffer
@ stdcall clEnqueueMapImage( long long long long ptr ptr ptr ptr long ptr ptr ptr ) wine_clEnqueueMapImage
@ stdcall clEnqueueUnmapMemObject( long long ptr long ptr ptr ) wine_clEnqueueUnmapMemObject
@ stdcall clEnqueueNDRangeKernel( long long long ptr ptr ptr long ptr ptr ) wine_clEnqueueNDRangeKernel
@ stdcall clEnqueueTask( long long long ptr ptr ) wine_clEnqueueTask
@ stdcall clEnqueueNativeKernel(long ptr ptr long long ptr ptr long ptr ptr) wine_clEnqueueNativeKernel
@ stdcall clEnqueueMarker( long ptr ) wine_clEnqueueMarker
@ stdcall clEnqueueWaitForEvents( long long ptr ) wine_clEnqueueWaitForEvents
@ stdcall clEnqueueBarrier( long ) wine_clEnqueueBarrier

@ stdcall clGetExtensionFunctionAddress( str ) wine_clGetExtensionFunctionAddress

@ stub clCreateFromGLBuffer
@ stub clCreateFromGLTexture2D
@ stub clCreateFromGLTexture3D
@ stub clCreateFromGLRenderbuffer
@ stub clGetGLObjectInfo
@ stub clGetGLTextureInfo
@ stub clEnqueueAcquireGLObjects
@ stub clEnqueueReleaseGLObjects
# @ stdcall clCreateFromGLBuffer( long long long ptr ) wine_clCreateFromGLBuffer
# @ stdcall clCreateFromGLTexture2D( long long long long long ptr ) wine_clCreateFromGLTexture2D
# @ stdcall clCreateFromGLTexture3D( long long long long long ptr ) wine_clCreateFromGLTexture3D
# @ stdcall clCreateFromGLRenderbuffer( long long long ptr ) wine_clCreateFromGLRenderbuffer
# @ stdcall clGetGLObjectInfo( long ptr ptr ) wine_clGetGLObjectInfo
# @ stdcall clGetGLTextureInfo( long long long ptr ptr ) wine_clGetGLTextureInfo
# @ stdcall clEnqueueAcquireGLObjects( long long ptr long ptr ptr ) wine_clEnqueueAcquireGLObjects
# @ stdcall clEnqueueReleaseGLObjects( long long ptr long ptr ptr ) wine_clEnqueueReleaseGLObjects

# OpenCL 1.1
@ stdcall clCreateSubBuffer( long long long ptr ptr ) wine_clCreateSubBuffer
@ stdcall clCreateUserEvent( long ptr ) wine_clCreateUserEvent
@ stdcall clEnqueueCopyBufferRect( long long long ptr ptr ptr long long long long long ptr ptr ) wine_clEnqueueCopyBufferRect
@ stdcall clEnqueueReadBufferRect( long long long ptr ptr ptr long long long long ptr long ptr ptr ) wine_clEnqueueReadBufferRect
@ stdcall clEnqueueWriteBufferRect( long long long ptr ptr ptr long long long long ptr long ptr ptr ) wine_clEnqueueWriteBufferRect
@ stdcall clSetEventCallback( long long ptr ptr ) wine_clSetEventCallback
@ stdcall clSetMemObjectDestructorCallback( long ptr ptr ) wine_clSetMemObjectDestructorCallback
@ stdcall clSetUserEventStatus( long long ) wine_clSetUserEventStatus

# OpenCL 1.2
@ stdcall clCompileProgram( long long ptr str long ptr ptr ptr ptr ) wine_clCompileProgram
@ stub clCreateFromGLTexture
@ stdcall clCreateImage( long long ptr ptr ptr ptr ) wine_clCreateImage
@ stdcall clCreateProgramWithBuiltInKernels( long long ptr str ptr ) wine_clCreateProgramWithBuiltInKernels
@ stdcall clCreateSubDevices( long ptr long ptr ptr ) wine_clCreateSubDevices
@ stdcall clEnqueueBarrierWithWaitList( long long ptr ptr ) wine_clEnqueueBarrierWithWaitList
@ stdcall clEnqueueFillBuffer( long long ptr long long long long ptr ptr ) wine_clEnqueueFillBuffer
@ stdcall clEnqueueFillImage( long long ptr ptr ptr long ptr ptr ) wine_clEnqueueFillImage
@ stdcall clEnqueueMarkerWithWaitList( long long ptr ptr ) wine_clEnqueueMarkerWithWaitList
@ stdcall clEnqueueMigrateMemObjects( long long ptr long long ptr ptr ) wine_clEnqueueMigrateMemObjects
@ stdcall clGetExtensionFunctionAddressForPlatform( long str ) wine_clGetExtensionFunctionAddressForPlatform
@ stdcall clGetKernelArgInfo( long long long long ptr ptr ) wine_clGetKernelArgInfo
@ stdcall clLinkProgram( long long ptr str long ptr ptr ptr ptr ) wine_clLinkProgram
@ stdcall clReleaseDevice( long ) wine_clReleaseDevice
@ stdcall clRetainDevice( long ) wine_clRetainDevice
@ stdcall clUnloadPlatformCompiler( long ) wine_clUnloadPlatformCompiler
=======
@ stdcall clBuildProgram(ptr long ptr ptr ptr ptr)
@ stdcall clCompileProgram(ptr long ptr ptr long ptr ptr ptr ptr)
@ stdcall clCreateBuffer(ptr int64 long ptr ptr)
@ stdcall clCreateCommandQueue(ptr ptr int64 ptr)
@ stdcall clCreateContext(ptr long ptr ptr ptr ptr)
@ stdcall clCreateContextFromType(ptr int64 ptr ptr ptr)
@ stdcall clCreateFromGLBuffer(ptr int64 long ptr)
@ stdcall clCreateFromGLRenderbuffer(ptr int64 long ptr)
@ stdcall clCreateFromGLTexture(ptr int64 long long long ptr)
@ stdcall clCreateFromGLTexture2D(ptr int64 long long long ptr)
@ stdcall clCreateFromGLTexture3D(ptr int64 long long long ptr)
@ stdcall clCreateImage(ptr int64 ptr ptr ptr ptr)
@ stdcall clCreateImage2D(ptr int64 ptr long long long ptr ptr)
@ stdcall clCreateImage3D(ptr int64 ptr long long long long long ptr ptr)
@ stdcall clCreateKernel(ptr ptr ptr)
@ stdcall clCreateKernelsInProgram(ptr long ptr ptr)
@ stdcall clCreateProgramWithBinary(ptr long ptr ptr ptr ptr ptr)
@ stdcall clCreateProgramWithBuiltInKernels(ptr long ptr ptr ptr)
@ stdcall clCreateProgramWithSource(ptr long ptr ptr ptr)
@ stdcall clCreateSampler(ptr long long long ptr)
@ stdcall clCreateSubBuffer(ptr int64 long ptr ptr)
@ stdcall clCreateSubDevices(ptr ptr long ptr ptr)
@ stdcall clCreateUserEvent(ptr ptr)
@ stdcall clEnqueueAcquireGLObjects(ptr long ptr long ptr ptr)
@ stdcall clEnqueueBarrier(ptr)
@ stdcall clEnqueueBarrierWithWaitList(ptr long ptr ptr)
@ stdcall clEnqueueCopyBuffer(ptr ptr ptr long long long long ptr ptr)
@ stdcall clEnqueueCopyBufferRect(ptr ptr ptr ptr ptr ptr long long long long long ptr ptr)
@ stdcall clEnqueueCopyBufferToImage(ptr ptr ptr long ptr ptr long ptr ptr)
@ stdcall clEnqueueCopyImage(ptr ptr ptr ptr ptr ptr long ptr ptr)
@ stdcall clEnqueueCopyImageToBuffer(ptr ptr ptr ptr ptr long long ptr ptr)
@ stdcall clEnqueueFillBuffer(ptr ptr ptr long long long long ptr ptr)
@ stdcall clEnqueueFillImage(ptr ptr ptr ptr ptr long ptr ptr)
@ stdcall clEnqueueMapBuffer(ptr ptr long int64 long long long ptr ptr ptr)
@ stdcall clEnqueueMapImage(ptr ptr long int64 ptr ptr ptr ptr long ptr ptr ptr)
@ stdcall clEnqueueMarker(ptr ptr)
@ stdcall clEnqueueMarkerWithWaitList(ptr long ptr ptr)
@ stdcall clEnqueueMigrateMemObjects(ptr long ptr int64 long ptr ptr)
@ stdcall clEnqueueNDRangeKernel(ptr ptr long ptr ptr ptr long ptr ptr)
@ stdcall clEnqueueNativeKernel(ptr ptr ptr long long ptr ptr long ptr ptr)
@ stdcall clEnqueueReadBuffer(ptr ptr long long long ptr long ptr ptr)
@ stdcall clEnqueueReadBufferRect(ptr ptr long ptr ptr ptr long long long long ptr long ptr ptr)
@ stdcall clEnqueueReadImage(ptr ptr long ptr ptr long long ptr long ptr ptr)
@ stdcall clEnqueueReleaseGLObjects(ptr long ptr long ptr ptr)
@ stdcall clEnqueueTask(ptr ptr long ptr ptr)
@ stdcall clEnqueueUnmapMemObject(ptr ptr ptr long ptr ptr)
@ stdcall clEnqueueWaitForEvents(ptr long ptr)
@ stdcall clEnqueueWriteBuffer(ptr ptr long long long ptr long ptr ptr)
@ stdcall clEnqueueWriteBufferRect(ptr ptr long ptr ptr ptr long long long long ptr long ptr ptr)
@ stdcall clEnqueueWriteImage(ptr ptr long ptr ptr long long ptr long ptr ptr)
@ stdcall clFinish(ptr)
@ stdcall clFlush(ptr)
@ stdcall clGetCommandQueueInfo(ptr long long ptr ptr)
@ stdcall clGetContextInfo(ptr long long ptr ptr)
@ stdcall clGetDeviceIDs(ptr int64 long ptr ptr)
@ stdcall clGetDeviceInfo(ptr long long ptr ptr)
@ stdcall clGetEventInfo(ptr long long ptr ptr)
@ stdcall clGetEventProfilingInfo(ptr long long ptr ptr)
@ stdcall clGetExtensionFunctionAddress(ptr)
@ stdcall clGetExtensionFunctionAddressForPlatform(ptr ptr)
@ stdcall clGetGLObjectInfo(ptr ptr ptr)
@ stdcall clGetGLTextureInfo(ptr long long ptr ptr)
@ stdcall clGetImageInfo(ptr long long ptr ptr)
@ stdcall clGetKernelArgInfo(ptr long long long ptr ptr)
@ stdcall clGetKernelInfo(ptr long long ptr ptr)
@ stdcall clGetKernelWorkGroupInfo(ptr ptr long long ptr ptr)
@ stdcall clGetMemObjectInfo(ptr long long ptr ptr)
@ stdcall clGetPlatformIDs(long ptr ptr)
@ stdcall clGetPlatformInfo(ptr long long ptr ptr)
@ stdcall clGetProgramBuildInfo(ptr ptr long long ptr ptr)
@ stdcall clGetProgramInfo(ptr long long ptr ptr)
@ stdcall clGetSamplerInfo(ptr long long ptr ptr)
@ stdcall clGetSupportedImageFormats(ptr int64 long long ptr ptr)
@ stdcall clLinkProgram(ptr long ptr ptr long ptr ptr ptr ptr)
@ stdcall clReleaseCommandQueue(ptr)
@ stdcall clReleaseContext(ptr)
@ stdcall clReleaseDevice(ptr)
@ stdcall clReleaseEvent(ptr)
@ stdcall clReleaseKernel(ptr)
@ stdcall clReleaseMemObject(ptr)
@ stdcall clReleaseProgram(ptr)
@ stdcall clReleaseSampler(ptr)
@ stdcall clRetainCommandQueue(ptr)
@ stdcall clRetainContext(ptr)
@ stdcall clRetainDevice(ptr)
@ stdcall clRetainEvent(ptr)
@ stdcall clRetainKernel(ptr)
@ stdcall clRetainMemObject(ptr)
@ stdcall clRetainProgram(ptr)
@ stdcall clRetainSampler(ptr)
@ stdcall clSetCommandQueueProperty(ptr int64 long ptr)
@ stdcall clSetEventCallback(ptr long ptr ptr)
@ stdcall clSetKernelArg(ptr long long ptr)
@ stdcall clSetMemObjectDestructorCallback(ptr ptr ptr)
@ stdcall clSetUserEventStatus(ptr long)
@ stdcall clUnloadCompiler()
@ stdcall clUnloadPlatformCompiler(ptr)
@ stdcall clWaitForEvents(long ptr)
>>>>>>> github-desktop-wine-mirror/master
