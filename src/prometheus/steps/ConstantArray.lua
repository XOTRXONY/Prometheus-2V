local Step = require("prometheus.step")
local Ast = require("prometheus.ast")
local Scope = require("prometheus.scope")
local visitast = require("prometheus.visitast")
local util = require("prometheus.util")
local Parser = require("prometheus.parser")
local enums = require("prometheus.enums")

local LuaVersion = enums.LuaVersion
local AstKind = Ast.AstKind

local ConstantArray = Step:extend()
ConstantArray.Description =
	"This Step will Extract all Constants and put them into an Array at the beginning of the script"
ConstantArray.Name = "Constant Array"

ConstantArray.SettingsDescriptor = {
	Treshold = {
		name = "Treshold",
		description = "The relative amount of nodes that will be affected",
		type = "number",
		default = 1,
		min = 0,
		max = 1,
	},
	StringsOnly = {
		name = "StringsOnly",
		description = "Wether to only Extract Strings",
		type = "boolean",
		default = false,
	},
	Shuffle = {
		name = "Shuffle",
		description = "Wether to shuffle the order of Elements in the Array",
		type = "boolean",
		default = true,
	},
	Rotate = {
		name = "Rotate",
		description = "Wether to rotate the String Array by a specific (random) amount. This will be undone on runtime.",
		type = "boolean",
		default = true,
	},
	LocalWrapperTreshold = {
		name = "LocalWrapperTreshold",
		description = "The relative amount of nodes functions, that will get local wrappers",
		type = "number",
		default = 1,
		min = 0,
		max = 1,
	},
	LocalWrapperCount = {
		name = "LocalWrapperCount",
		description = "The number of Local wrapper Functions per scope. This only applies if LocalWrapperTreshold is greater than 0",
		type = "number",
		min = 0,
		max = 512,
		default = 0,
	},
	LocalWrapperArgCount = {
		name = "LocalWrapperArgCount",
		description = "The number of Arguments to the Local wrapper Functions",
		type = "number",
		min = 1,
		default = 10,
		max = 200,
	},
	MaxWrapperOffset = {
		name = "MaxWrapperOffset",
		description = "The Max Offset for the Wrapper Functions",
		type = "number",
		min = 0,
		default = 65535,
	},
	Encoding = {
		name = "Encoding",
		description = "The Encoding to use for the Strings",
		type = "enum",
		default = "base64",
		values = {
			"none",
			"base64",
		},
	},
}

local function callNameGenerator(generatorFunction, ...)
	if type(generatorFunction) == "table" then
		generatorFunction = generatorFunction.generateName
	end
	return generatorFunction(...)
end

local math = require("math")
math.randomseed(os.time())

local function generate_random_suffix()
	local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	local suffix = ""
	local length = math.random(5, 10)
	for i = 1, length do
		local rand = math.random(1, #chars)
		suffix = suffix .. string.sub(chars, rand, rand)
	end
	return suffix
end

local junk_patterns = {
	"local a = 1; a = nil;",
	"if false then end;",
	"local useless_var" .. math.random(1000) .. " = " .. math.random(1, 100) .. " + " .. math.random(1, 100) .. "; ",
	"for i=1, " .. math.random(3, 10) .. " do end;",
	"if " .. math.random(0, 1) .. " == 0 then local fake = nil; else end;",
	"local rand_table = {" .. table.concat({ math.random(1, 10), math.random(1, 10) }, ",") .. "}; rand_table = nil;",
	"function fake_func() return " .. math.random(1, 100) .. "; end; fake_func = nil;",
}

function ConstantArray:init(settings) end

function ConstantArray:createArray()
	local entries = {}
	for i, v in ipairs(self.constants) do
		if type(v) == "string" then
			v = self:encode(v)
		end
		entries[i] = Ast.TableEntry(Ast.ConstantNode(v))
	end
	return Ast.TableConstructorExpression(entries)
end

function ConstantArray:indexing(index, data)
	if self.LocalWrapperCount > 0 and data.functionData.local_wrappers then
		local wrappers = data.functionData.local_wrappers
		local wrapper = wrappers[math.random(#wrappers)]

		local args = {}
		local ofs = index - self.wrapperOffset - wrapper.offset
		for i = 1, self.LocalWrapperArgCount, 1 do
			if i == wrapper.arg then
				args[i] = Ast.NumberExpression(ofs)
			else
				args[i] = Ast.NumberExpression(math.random(ofs - 1024, ofs + 1024))
			end
		end

		data.scope:addReferenceToHigherScope(wrappers.scope, wrappers.id)
		return Ast.FunctionCallExpression(
			Ast.IndexExpression(
				Ast.VariableExpression(wrappers.scope, wrappers.id),
				Ast.StringExpression(wrapper.index)
			),
			args
		)
	else
		data.scope:addReferenceToHigherScope(self.rootScope, self.wrapperId)
		return Ast.FunctionCallExpression(Ast.VariableExpression(self.rootScope, self.wrapperId), {
			Ast.NumberExpression(index - self.wrapperOffset),
		})
	end
end

function ConstantArray:getConstant(value, data)
	if self.lookup[value] then
		return self:indexing(self.lookup[value], data)
	end
	local idx = #self.constants + 1
	self.constants[idx] = value
	self.lookup[value] = idx
	return self:indexing(idx, data)
end

function ConstantArray:addConstant(value)
	if self.lookup[value] then
		return self.lookup[value]
	end
	local idx = #self.constants + 1
	self.constants[idx] = value
	self.lookup[value] = idx
	return idx
end

function ConstantArray:encode(str)
	if self.Encoding == "base64" then
		return util.base64encode(str)
	end
	return str
end

function ConstantArray:decode(str)
	if self.Encoding == "base64" then
		return util.base64decode(str)
	end
	return str
end

function ConstantArray:addDecodeCode(ast)
	if self.Encoding == "base64" then
		local code = [[
local charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
local function base64decode(str)
	local data = "";
	local i = 1;
	while i <= #str do
		local enc = "";
		for j = 1, 4 do
			local char = str:sub(i, i);
			i = i + 1;
			if char == "=" then
				break;
			end
			enc = enc .. string.format("%06d", charset:find(char, 1, true) - 1):reverse();
		end
		for j = 1, #enc / 8 do
			data = data .. string.char(tonumber(enc:sub(j * 8 - 7, j * 8):reverse(), 2));
		end
	end
	return data;
end
]]
		local parsed = Parser:new({ LuaVersion = LuaVersion.Lua51 }):parse(code)
		parsed.body.scope:setParent(ast.body.scope)
		for i, stat in ipairs(parsed.body.statements) do
			table.insert(ast.body.statements, i, stat)
		end
	end
end

function ConstantArray:addRotateCode(ast, shift)
	local code = string.format(
		[[
local function rotate(arr, shift)
	local len = #arr;
	shift = shift %% len;
	for i = 1, shift do
		table.insert(arr, 1, table.remove(arr));
	end
end
rotate(%s, %d);
]],
		self.rootScope:getVariableName(self.arrId),
		shift
	)
	local parsed = Parser:new({ LuaVersion = LuaVersion.Lua51 }):parse(code)
	parsed.body.scope:setParent(ast.body.scope)
	for i, stat in ipairs(parsed.body.statements) do
		table.insert(ast.body.statements, i + 1, stat)
	end
end

function ConstantArray:insert_junk(ast, pipeline)
	local isStrongMode = pipeline.config.preset == "Strong"
	if not isStrongMode then
		return
	end
	local count = math.random(5, 15)
	for i = 1, count do
		local pattern = junk_patterns[math.random(#junk_patterns)]
		local parsed = Parser:new({ LuaVersion = LuaVersion.Lua51 }):parse(pattern)
		table.insert(ast.body.statements, math.random(1, #ast.body.statements + 1), parsed.body.statements[1])
	end
end

function ConstantArray:apply(ast, pipeline)
	self.constants = {}
	self.lookup = {}
	self.rootScope = Scope:new(ast.body.scope:getGlobalScope())

	local isStrongMode = pipeline.config.preset == "Strong"
	local arrVarName = isStrongMode and "Du8Nb" .. generate_random_suffix() or "M"

	self.arrId = self.rootScope:addVariable(arrVarName)
	self.wrapperId = self.rootScope:addVariable()
	self.wrapperOffset = math.random(-self.MaxWrapperOffset, self.MaxWrapperOffset)

	visitast(ast, function(node, data)
		if
			node.kind == AstKind.FunctionLiteralExpression
			or node.kind == AstKind.FunctionDeclaration
			or node.kind == AstKind.LocalFunctionDeclaration
		then
			data.functionData = {}
			if math.random() <= self.LocalWrapperTreshold then
				data.functionData.local_wrappers = {}
				data.functionData.scope = Scope:new(node.scope)
				data.functionData.id = data.functionData.scope:addVariable()
				local wrappers = data.functionData.local_wrappers
				local nameLookup = {}
				for i = 1, self.LocalWrapperCount, 1 do
					local name
					repeat
						name = callNameGenerator(pipeline.namegenerator, math.random(1, self.LocalWrapperArgCount * 16))
					until not nameLookup[name]
					nameLookup[name] = true

					local offset = math.random(-self.MaxWrapperOffset, self.MaxWrapperOffset)
					local argPos = math.random(1, self.LocalWrapperArgCount)

					data.functionData.local_wrappers[i] = {
						arg = argPos,
						index = name,
						offset = offset,
					}
					data.functionData.__used = false
				end
			end
			if node.__apply_constant_array then
				data.functionData.__used = true
			end
		end
	end, function(node, data)
		if node.__apply_constant_array then
			if node.kind == AstKind.StringExpression then
				return self:getConstant(node.value, data)
			elseif not self.StringsOnly then
				if node.isConstant then
					return node.value ~= nil and self:getConstant(node.value, data)
				end
			end
			node.__apply_constant_array = nil
		end

		if
			self.LocalWrapperCount > 0
			and node.kind == AstKind.Block
			and node.isFunctionBlock
			and data.functionData.local_wrappers
			and data.functionData.__used
		then
			data.functionData.__used = nil
			local elems = {}
			local wrappers = data.functionData.local_wrappers
			for i = 1, self.LocalWrapperCount, 1 do
				local wrapper = wrappers[i]
				local argPos = wrapper.arg
				local offset = wrapper.offset
				local name = wrapper.index

				local funcScope = Scope:new(node.scope)

				local arg = nil
				local args = {}

				for i = 1, self.LocalWrapperArgCount, 1 do
					args[i] = funcScope:addVariable()
					if i == argPos then
						arg = args[i]
					end
				end

				local addSubArg

				if offset < 0 then
					addSubArg = Ast.SubExpression(Ast.VariableExpression(funcScope, arg), Ast.NumberExpression(-offset))
				else
					addSubArg = Ast.AddExpression(Ast.VariableExpression(funcScope, arg), Ast.NumberExpression(offset))
				end

				funcScope:addReferenceToHigherScope(self.rootScope, self.wrapperId)
				local callArg = Ast.FunctionCallExpression(Ast.VariableExpression(self.rootScope, self.wrapperId), {
					addSubArg,
				})

				local fargs = {}
				for i, v in ipairs(args) do
					fargs[i] = Ast.VariableExpression(funcScope, v)
				end

				elems[i] = Ast.KeyedTableEntry(
					Ast.StringExpression(name),
					Ast.FunctionLiteralExpression(
						fargs,
						Ast.Block({
							Ast.ReturnStatement({
								callArg,
							}),
						}, funcScope)
					)
				)
			end
			table.insert(
				node.statements,
				1,
				Ast.LocalVariableDeclaration(node.scope, {
					wrappers.id,
				}, {
					Ast.TableConstructorExpression(elems),
				})
			)
		end
	end)

	self:addDecodeCode(ast)

	local steps = util.shuffle({

		function()
			local funcScope = Scope:new(self.rootScope)

			funcScope:addReferenceToHigherScope(self.rootScope, self.arrId)

			local arg = funcScope:addVariable()
			local addSubArg

			if self.wrapperOffset < 0 then
				addSubArg =
					Ast.SubExpression(Ast.VariableExpression(funcScope, arg), Ast.NumberExpression(-self.wrapperOffset))
			else
				addSubArg =
					Ast.AddExpression(Ast.VariableExpression(funcScope, arg), Ast.NumberExpression(self.wrapperOffset))
			end

			table.insert(
				ast.body.statements,
				1,
				Ast.LocalFunctionDeclaration(
					self.rootScope,
					self.wrapperId,
					{
						Ast.VariableExpression(funcScope, arg),
					},
					Ast.Block({
						Ast.ReturnStatement({
							Ast.IndexExpression(Ast.VariableExpression(self.rootScope, self.arrId), addSubArg),
						}),
					}, funcScope)
				)
			)
		end,

		function()
			if self.Rotate and #self.constants > 1 then
				local shift = math.random(1, #self.constants - 1)

				rotate(self.constants, -shift)
				self:addRotateCode(ast, shift)
			end
		end,
	})

	for i, f in ipairs(steps) do
		f()
	end

	table.insert(
		ast.body.statements,
		1,
		Ast.LocalVariableDeclaration(self.rootScope, { self.arrId }, { self:createArray() })
	)

	self:insert_junk(ast, pipeline)

	self.rootScope = nil
	self.arrId = nil

	self.constants = nil
	self.lookup = nil
end

return ConstantArray
