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

#include "lookup3.c"

static uint32_t one_at_a_time(const char *key, Py_ssize_t key_len) {
  Py_ssize_t i;
  uint32_t hash = 0;

  for (i = 0; i < key_len; ++i) {
    hash += key[i];
    hash += (hash << 10);
    hash ^= (hash >> 6);
  }

  hash += (hash << 3);
  hash ^= (hash >> 11);
  hash += (hash << 15);

  return hash;
}

static PyObject* oneatatime_py(PyObject* self, PyObject* args) {
  const char *key = NULL;
  Py_ssize_t key_len;
  uint32_t hash;

  // Extract the python unicode argument
  if (!PyArg_ParseTuple(args, "es#", "UTF-8", &key, &key_len))
    return NULL;

  hash = one_at_a_time(key, key_len);

  PyMem_Free((void *) key);
  return Py_BuildValue("I", hash);
}

static char oneatatime_doc[] = "Bob Jenkins's One-at-a-time non-cryptographic hash function. Takes a unicode and returns an unsigned 32-bit integer.";

static char hashword_doc[] = "hashword(sequence, unsigned number):\nThis works on all machines.  To be useful, it requires\nthat the key be an array (python sequence) of uint32_t's\nThe function hashword() is identical to hashlittle() on little-endian\nmachines, and identical to hashbig() on big-endian machines,\nexcept that the length has to be measured in uint32_ts rather than in\nbytes.  hashlittle() is more complicated than hashword() only because\nhashlittle() has to dance around fitting the key bytes into registers.";

static PyObject* hashword_py(PyObject* self, PyObject* args) {
  uint32_t hash;
  uint32_t *key; /* C representation of the input sequence */
  Py_ssize_t key_len, i;
  unsigned long initval = 0;
  PyObject *obj, *seq; /* The sequence object */
  PyObject *tmp, *lng; /* The current item in the sequence */

  /* Get arguments and make sure they're the correct type */
  if (!PyArg_ParseTuple(args, "O|k", &obj, &initval))
    return NULL;

  seq = PySequence_Fast(obj, "first parameter must be a sequence");
  if (!seq)
    return NULL;

  /* Convert the sequence to a C array */
  key_len = PySequence_Fast_GET_SIZE(seq);
  if (key_len == -1) {
    Py_DECREF(seq);
    return NULL;
  }

  if (key_len == 0) {
    PyErr_SetString(PyExc_ValueError, "Provided sequence must not be empty");
    Py_DECREF(seq);
    return NULL;
  }

  key = malloc(sizeof(uint32_t)*key_len);
  if (!key) {
    Py_DECREF(seq);
    return PyErr_NoMemory();
  }

  for (i = 0; i < key_len; ++i) {
    tmp = PySequence_Fast_GET_ITEM(seq, i);
    if (!tmp) {
      free(key);
      Py_DECREF(seq);
      return NULL;
    }

    lng = PyNumber_Long(tmp);
    if (!lng) {
      free(key);
      Py_DECREF(seq);
      return NULL;
    }

    key[i] = (uint32_t) PyLong_AsUnsignedLong(lng);

    Py_DECREF(lng);
  }

  Py_DECREF(seq);

  /* Actually hash */
  hash = hashword(key, (size_t) key_len, (uint32_t) initval);

  free(key);
  return Py_BuildValue("I", hash);
}

static char hashword2_doc[] = "hashword2() -- same as hashword(), but take two seeds and return two\n32-bit values.  pc and pb must both be nonnull, and *pc and *pb must\nboth be initialized with seeds.  If you pass in (*pb)==0, the output\n(*pc) will be the same as the return value from hashword().";

static PyObject* hashword2_py(PyObject* self, PyObject* args) {
  uint32_t *key; /* C representation of the input sequence */
  Py_ssize_t key_len, i;
  unsigned long initpc = 0;
  unsigned long initpb = 0;
  uint32_t pc, pb;
  PyObject *obj, *seq; /* The sequence object */
  PyObject *tmp, *lng; /* The current item in the sequence */

  /* Get arguments and make sure they're the correct type */
  if (!PyArg_ParseTuple(args, "O|kk", &obj, &initpc, &initpb))
    return NULL;

  seq = PySequence_Fast(obj, "first parameter must be a sequence");
  if (!seq)
    return NULL;

  /* Convert the sequence to a C array */
  key_len = PySequence_Fast_GET_SIZE(seq);
  if (key_len == -1) {
    Py_DECREF(seq);
    return NULL;
  }

  if (key_len == 0) {
    PyErr_SetString(PyExc_ValueError, "Provided sequence must not be empty");
    Py_DECREF(seq);
    return NULL;
  }

  key = malloc(sizeof(uint32_t)*key_len);
  if (!key) {
    Py_DECREF(seq);
    return PyErr_NoMemory();
  }

  for (i = 0; i < key_len; ++i) {
    tmp = PySequence_Fast_GET_ITEM(seq, i);
    if (!tmp) {
      free(key);
      Py_DECREF(seq);
      return NULL;
    }

    lng = PyNumber_Long(tmp);
    if (!lng) {
      free(key);
      Py_DECREF(seq);
      return NULL;
    }

    key[i] = (uint32_t) PyLong_AsUnsignedLong(lng);

    Py_DECREF(lng);
  }

  Py_DECREF(seq);

  /* Actually hash */
  pc = (uint32_t) initpc;
  pb = (uint32_t) initpb;
  hashword2(key, (size_t) key_len, &pc, &pb);

  free(key);
  return Py_BuildValue("(II)", pc, pb);
}

static PyObject* hashlittle_py(PyObject* self, PyObject* args) {
  return NULL;
}

static PyObject* hashlittle2_py(PyObject* self, PyObject* args) {
  return NULL;
}

static PyObject* hashbig_py(PyObject* self, PyObject* args) {
  return NULL;
}

static PyObject* mix_py(PyObject* self, PyObject* args) {
  return NULL;
}

static PyObject* final_py(PyObject* self, PyObject* args) {
  return NULL;
}

static PyMethodDef jenkins_funcs[] = {
  {"oneatatime", (PyCFunction) oneatatime_py, METH_VARARGS, oneatatime_doc},
  {"hashword",   (PyCFunction) hashword_py,   METH_VARARGS, hashword_doc},
  {"hashword2",  (PyCFunction) hashword2_py,  METH_VARARGS, hashword2_doc},
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
