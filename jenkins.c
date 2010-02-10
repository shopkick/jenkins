/*
  Copyright (c) 2010, Will Ashford
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in
    the documentation and/or other materials provided with the
    distribution.

  * Neither the name of the copyright holder nor the names of
    contributors may be used to endorse or promote products derived
    from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
  COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
 */
#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <stdint.h>

static PyObject* oneatatime(PyObject* self, PyObject* args) {
  const char *key = NULL;
  Py_ssize_t key_len, i;
  uint32_t hash = 0;

  // Extract the python unicode argument
  if (!PyArg_ParseTuple(args, "es#", "UTF-8", &key, &key_len))
    return NULL;

  for (i = 0; i < key_len; ++i) {
    hash += key[i];
    hash += (hash << 10);
    hash ^= (hash >> 6);
  }

  hash += (hash << 3);
  hash ^= (hash >> 11);
  hash += (hash << 15);

  PyMem_Free((void *) key);
  return Py_BuildValue("I", hash);
}

static char oneatatime_doc[] = "Bob Jenkins's One-at-a-time non-cryptographic hash function. Takes a unicode and returns an unsigned 32-bit integer.";

static PyMethodDef jenkins_funcs[] = {
  {"oneatatime", (PyCFunction) oneatatime, METH_VARARGS, oneatatime_doc},
  {NULL, NULL, 0, NULL}
};

static const char jenkins_doc[] = "Bob Jenkins's hash functions published at http://www.burtleburtle.net/bob/hash/doobs.html.";

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef jenkins = {
  PyModuleDef_HEAD_INIT,
  "jenkins",
  jenkins_doc,
  -1,
  jenkins_funcs
};

PyMODINIT_FUNC PyInit_jenkins(void) {
  return PyModule_Create(&jenkins);
}
#else
PyMODINIT_FUNC initjenkins(void) {
  (void) Py_InitModule3("jenkins", jenkins_funcs, jenkins_doc);
}
#endif
