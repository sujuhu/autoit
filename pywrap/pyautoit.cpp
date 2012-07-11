// pyautoit.cpp : Defines the entry point for the console application.
//
#pragma warning( disable:4996 )
#include <stdlib.h>
//#include <windows.h>
#include <Python.h>
#include "../src/autoit.h"

/*
Check whether we got a Python Object
*/
PyObject *check_object(PyObject *pObject)
{
  PyObject *pException;

  if(!pObject) {
    pException = PyErr_Occurred();
    if(pException)
      PyErr_Print();
    return NULL;
  }

  return pObject;
}

extern "C"
PyObject* pyautoit_dump_script(PyObject* self, PyObject* args) 
{ 
  if(!args || PyObject_Length(args)!=3) {
    PyErr_SetString(PyExc_TypeError,
      "Invalid number of arguments, 3 expected: (stream, stream_size, logfile)");
    return NULL;
  }

  PyObject* py_stream = PyTuple_GetItem(args, 0);
  if(!check_object(py_stream)) {
    PyErr_SetString(PyExc_ValueError, "Can't get stream from arguments");
  }

  PyObject* py_size = PyTuple_GetItem(args, 1);
  if(!check_object(py_size)) {
    PyErr_SetString(PyExc_ValueError, "Can't get size from arguments");
  }

  PyObject* py_logfile = PyTuple_GetItem(args, 2);
  if(!check_object(py_logfile)) {
    PyErr_SetString(PyExc_ValueError, "Can't get logfile from arguments");
  }

  char* stream = PyString_AsString(py_stream);
  size_t stream_size = PyLong_AsLong(py_size);
  char* logfile = PyString_AsString(py_logfile);
	
	const char* stream_autoit = au_open_script(stream, stream_size );
  if (stream == NULL){
    Py_RETURN_FALSE;
  }

  stream_size = stream_size - (stream_autoit - stream );
  if (!au_dump_script(logfile, stream_autoit, stream_size)){
    Py_RETURN_FALSE;
  }

  Py_RETURN_TRUE;
} 

static PyMethodDef autoitMethods[] =
{ 
	{"dump_script",		pyautoit_dump_script,	METH_VARARGS, "Execute a shell command."}, 
	{NULL, NULL, 0, NULL}
}; 

PyMODINIT_FUNC initpyautoit() 
{ 
	Py_InitModule("pyautoit", autoitMethods); 
} 