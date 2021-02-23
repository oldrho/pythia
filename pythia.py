#!/usr/bin/env python3

import base64
import sys
import requests
import time
import queue
import threading
import random
import json



class Stream:
	def __init__(self, block_length, oracle, threads=100, verbose=False):
		self.block_length = block_length
		self.oracle = oracle
		self.threads = threads
		self.verbose = verbose

	def decrypt(self, data):
		bl = self.block_length
		self.blocks = [Block(self, data[i*bl:i*bl+bl], index=i) for i in range(len(data)//bl)]
		if len(self.blocks) < 2:
			raise Exception

		# Get all intermediate values
		for block in self.blocks[1:][::-1]:
			if self.verbose:
				print("Decrypting block %d" % block.index)
			block.get_intermediate()

		# Decrypt ciphertexts and concatenate plaintexts
		result = bytes(sum([block.decrypt() for block in self.blocks[1:]],[]))

		# Validate padding
		pad_value = result[-1]
		if pad_value == 0 or pad_value > bl:
			raise Exception
		if not all([x == pad_value for x in result[-pad_value:]]):
			raise Exception

		return bytes(result[:-pad_value])

	def encrypt(self, data):
		bl = self.block_length

		# Convert and pad list correctly
		data = list(data)
		pad_value = bl-(len(data)%bl)
		if pad_value == 0:
			pad_value = bl
		data += [pad_value]*pad_value

		# Block count = IV + final ciphertext
		block_count = len(data)//bl

		# Create a random ciphertext block
		ciphertext = [random.randint(0,256) for x in range(bl)]
		result = ciphertext

		for i in range(block_count):
			block = Block(self, ciphertext)

			# Get the intermediate values
			block.get_intermediate()

			# Get plaintext to encrypt
			plaintext = data[-i*bl-bl:][:bl]

			# Create the ciphertext for the previous block that will XOR to give
			# the correct plaintext for this block
			ciphertext = block.encrypt_iv(plaintext)

			# Prepend the ciphertext to the result
			result = ciphertext + result

			if self.verbose:
				print("Encrypted block %d" % (block_count-i))

		return bytes(result)





class Block:
	def __init__(self, stream, ciphertext, index=None):
		self.stream = stream
		self.ciphertext = ciphertext
		self.index = index

		self.I = [0]*self.stream.block_length

	def get_intermediate(self):
		for n in range(1,self.stream.block_length + 1):
			self.get_position(n)

	def get_position(self, position):
		zeros = [0]*(self.stream.block_length-position)
		known = [position ^ i for i in self.I[-position+1:]][:position-1]

		result = [False]

		# Queue all guesses
		q = queue.Queue()
		for guess in range(0,256):
			q.put(guess)

		def threadfunc():
			while not q.empty():
				guess = q.get()

				# Create guess block
				guessblock = zeros + [position^guess] + known

				# Create guess message
				message = bytes(guessblock) + bytes(self.ciphertext)

				# Ask the oracle
				if self.stream.oracle(message):
					result[0] = guess
					self.I[-position] = result[0]

					with q.mutex:
						q.queue.clear()
					break

		threads = []
		for x in range(self.stream.threads):
			thread = threading.Thread(target=threadfunc)
			thread.start()
			threads.append(thread)

		for thread in threads:
			thread.join()

		return result[0]

	def decrypt(self):
		return [a^b for a,b in zip(self.stream.blocks[self.index-1].ciphertext, self.I)]
	
	def encrypt_iv(self, plaintext):
		if len(plaintext) != self.stream.block_length:
			raise Exception

		return [a^b for a,b in zip(plaintext, self.I)]
