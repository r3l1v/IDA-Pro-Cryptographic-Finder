import idautils
import idaapi
import ida_bytes
import ida_allins
import ida_funcs
from idc import set_color
from idc import get_color
import ida_ua
from queue import Queue
from prettytable import PrettyTable

instruction_list = [ida_allins.NN_xor,
                        ida_allins.NN_sal,
                        ida_allins.NN_sar,
                        ida_allins.NN_shl,
                        ida_allins.NN_shr,
                        ida_allins.NN_rol,
                        ida_allins.NN_ror,
                        ida_allins.NN_add,
                        ida_allins.NN_adc,
                        ida_allins.NN_rcl,
                        ida_allins.NN_rcr
                        #ida_allins.NN_lea,
                        #ida_allins.NN_test
                        ]

def density_search():
    """
    Function which counts the density of specified crypto instruction set and returns function/address with the highest count in raw binary
    This function does not go through the flow graph
    """

    q = Queue(maxsize = 30)
    counter = 0
    max_counter = 0
    chunk_max_addr = 0
    chunk_max_addr_dict = {}
    # there can be more then one found chunk so it is a dictionary

    # Iterating through all functions returned from IDA
    for function_eaddr in idautils.Functions():
        funct_t = ida_funcs.get_func(function_eaddr)
        # iterating trhough all instructions in the function, disassembling them
        for eaddr in idautils.Heads(funct_t.start_ea, funct_t.end_ea):
            insn = idaapi.insn_t()
            length = idaapi.decode_insn(insn, eaddr)
            # Filling a queue
            if not q.full():
                q.put(insn)
                if insn.itype in instruction_list:
                    counter += 1
            else:
                currently_dequed = q.get()
                # removed instruction is in the instruction_list
                if currently_dequed.itype in instruction_list:
                    counter -= 1
                q.put(insn)
                # placing new instruction to the queue and checking whether it is in instruction_list
                if insn.itype in instruction_list:
                    counter += 1
                    # saving a max chunk where the maximum number of "cryptographic" instructions were found
                    if counter >= max_counter:
                        max_counter = counter
                        chunk_max_addr = [q.queue[0].ea, q.queue[29].ea]
                        # Storing in dictionary, first checking if the key exists, if not, creating it
                        if max_counter not in chunk_max_addr_dict.keys():
                            chunk_max_addr_dict[max_counter] = [[q.queue[0].ea, q.queue[29].ea]]
                        else:
                            chunk_max_addr_dict[max_counter].append([q.queue[0].ea, q.queue[29].ea])
                        
    #print(max(chunk_max_addr_dict.keys()))
    #for value in chunk_max_addr_dict[max(chunk_max_addr_dict.keys())]:
        #print(hex(value))
    #print(chunk_max_addr_dict)

    return chunk_max_addr_dict

def address_in_block(address, block):
    """
    Function which returs boolean whether the address is in the basic block pointed by block

    @address - adress to search 
    @block - BasicBlock where address will be searched
    """
    if address > block.start_ea and address < block.end_ea:
        return 1
    return 0

def delete_fully_overlapping(non_trivial_loops, density_search_dict):
    """
    Function which deletes fully overlapping blocks from both searches
    @non_trivial_loops - list of strong components from Tarjans algorithm of size > 1
    @density_search_dict - dictionaru returned by density_search()
    """
    # Double looping through all possible combinations of blocks from both searches
    for density, blocks in density_search_dict.items():
        for address in blocks:
            for non_trivial_loop in non_trivial_loops:
                for block in non_trivial_loop:
                    # first situation from find_overlap()
                    if address[0] > block.start_ea and address[1] < block.end_ea:
                        # deleting the block
                        density_search_dict[density].remove(address)
                        return 1

    return 0

def find_overlap(non_trivial_loops, density_search_dict):
    """
    Function which finds an overlaps between blocks from both searches
    Tree situations
    1. block from density search is fully in the block from loop search
    2. block from density search starts in block from loop search but ends in different place
    3. block from density search ends in a block from loop search but starts in different place

    @non_trivial_loops - list of strong components from Tarjans algorithm of size > 1
    @density_search_dict - dictionary returned by density_search()

    Returns dictionary of new frequency/blocks values
    """

    # first situation
    # first deleting fully overlapping block
    while delete_fully_overlapping(non_trivial_loops, density_search_dict):
        pass

    # continuing to second and third situation
    # Double looping through all possible combinations of blocks from both searches
    merged_blocks = {}
    for density, blocks in density_search_dict.items():
        for address in blocks:

            for non_trivial_loop in non_trivial_loops:
                for block in non_trivial_loop:
           
                    # second situation
                    if address_in_block(address[0], block):
                        # appending the block (only if the address[1] is in blocks successors>)
                        for successor in block.succs():
                            if address_in_block(address[1],successor):

                                # only appending if there are more crypto instruction in their overlap, if not, ignore
                                difference = count_in_block(block.end_ea, address[1])
                                if difference > 0:
                                    # merging
                                    new_block = [block.start_ea, address[1]]
                                    count_in_new_block = count_in_block(new_block[0], new_block[1])
                                    # Storing in dictionary, first checking if the key exists, if not, creating it
                                    if count_in_new_block not in merged_blocks.keys():
                                        merged_blocks[count_in_new_block] = [new_block]
                                    else:
                                        merged_blocks[count_in_new_block].append(new_block)
                    # third situation
                    elif address_in_block(address[1], block):
                        # prepending the block (only if the address[1] is in blocks predecessors>)
                        for predecessor in block.preds():
                            if address_in_block(address[0],predecessor) :

                                # only prepending if there are more crypto instructions in their overlap, if not, ignore
                                difference = count_in_block(address[0], block.start_ea)
                                if difference > 0:
                                    # merging
                                    new_block = [address[0], block.end_ea]
                                    count_in_new_block = count_in_block(new_block[0], new_block[1])
                                    # Storing in dictionary, first checking if the key exists, if not, creating it
                                    if count_in_new_block not in merged_blocks.keys():
                                        merged_blocks[count_in_new_block] = [new_block]
                                    else:
                                        merged_blocks[count_in_new_block].append(new_block)
    return merged_blocks

def filtering_results(density_search_dict):
    """
    Function which filters out "duplicate results" from the density search
    if the found blocks are close together

    @density_search_dict - dictionary returned by density_search()
    """

    # Looping throuhg all blocks from density search and its addresses with i instructions
    for density, blocks in density_search_dict.items():
        for address in blocks:
            # disassembling the instructions
            function_address = ida_funcs.get_func(address[0])
            flow_chart = idaapi.FlowChart(function_address)

            for block in flow_chart:
                # finding a block in flow chart where the block from density search is 
                if address[0] > block.start_ea and address[1] < block.end_ea:

                    # found the block in flowchart
                    # loop through the rest of the blocks from density search and identify if any of them is in the 
                    # same flowchart block as well, if yes, merge them and delete them
                    for density_2, blocks_2 in density_search_dict.items():
                        for address_2 in blocks_2:

                            if address_2 == address:
                                continue
                            elif address_2[0] > block.start_ea and address_2[1] < block.end_ea:
                                # merge and delete address_2 block
                                if address_2[0] > address[0]:
                                    # new block is [address[0], address_2[1]]
                                    new_block = [address[0], address_2[1]]
                                else:
                                    # new block is [address_2[0], address[1]]
                                    new_block = [address_2[0], address[1]]

                                # recount crypto instruction in the new block
                                count_in_new_block = count_in_block(new_block[0], new_block[1])

                                # putting new block into the array and deleting the old one
                                density_search_dict[density].remove(address)
                                density_search_dict[density_2].remove(address_2)
                                # Storing in dictionary, first checking if the key exists, if not, creating it
                                if count_in_new_block not in density_search_dict.keys():
                                    density_search_dict[count_in_new_block] = [new_block]
                                else:
                                    density_search_dict[count_in_new_block].append(new_block)
                                return 1
    return 0


def filtering_results_correct(density_search_dict):
    return [filtering_block(blocks) for density, blocks in list(density_search_dict.items())]

def count_in_block(start_ea, end_ea):
    """
    Function that counts crypto instructions in block specified by start address and end address

    @start_ea - start address of block to search
    @end_ea   - send address of block to search

    Returns the number of instructions between start_ea and end_ea
    """
    counter = 0
    # loop through all instruciton addresses beteen start_ea and end_ea
    for eaddr in idautils.Heads(start_ea, end_ea):
        # disassembling the address
        insn = idaapi.insn_t()
        length = idaapi.decode_insn(insn, eaddr)
        # searching for instructions
        if insn.itype in instruction_list:
                counter += 1
    return counter

def count_in_loop(loop):
    """
    Functions that counts crypto instructions in loop (SCC component)

    @loop - list of BasicBlocks which is a strongly connected component from Tarjans algorithm

    Returns the number of instructions between start_ea and end_ea of all BasicBlocks in loop
    """
    counter = 0
    for block in loop:
        # loop through all instruciton addresses in block
        for eaddr in idautils.Heads(block.start_ea, block.end_ea):
            # disassembling the address
            insn = idaapi.insn_t()
            length = idaapi.decode_insn(insn, eaddr)
            # searching for instructions
            if insn.itype in instruction_list:
                counter += 1
    return counter

def SCC_for_current_vertex(current_vertex):
    """
    Helper function for Tarjans algorithm, recursively descends into neighbors of current_vertex and calculates strong connected component of current_vertex

    @current_vertex - node in a graph to calculate its strongly connected component
    """
    global result, stack, low, disc , index_counter, stackMember

    # set the depth index for this current_vertex.id to the smallest unused index
    disc[current_vertex.id] = index_counter[0]
    low[current_vertex.id] = index_counter[0]
    index_counter[0] += 1
    stackMember[current_vertex.id] = True
    stack.append(current_vertex)
    # Loading all successors of `current_vertex`
    try:
        successors = current_vertex.succs()
    except:
        successors = []
    # Iterating through all succors
    for successor in successors:
        if disc[successor.id] == -1:
            # block not visited yet
            SCC_for_current_vertex(successor)
            low[current_vertex.id] = min(low[current_vertex.id], low[successor.id])
        elif stackMember[successor.id]  == True:
            # the successor is in the stack and hence in the current strongly connected component (SCC)
            low[current_vertex.id] = min(low[current_vertex.id], disc[successor.id])

    # If `current_vertex.id` is a root current_vertex.id, pop the stack and generate an SCC
    w = -1
    if low[current_vertex.id] == disc[current_vertex.id]:
        connected_component = []
        while w != current_vertex.id:
            successor = stack.pop()
            w = successor.id
            connected_component.append(successor)
            stackMember[w] = False
        # storing the result
        result.append(connected_component)

def tarjan(flow_chart):
    """
    Function which performs Tarjans alrogithm on a graph

    @flow_chart - root node of IDA Flowchart graph

    Returns array of strongly connected components of graph pointed by flow_chart
    """
    global result, stack, low, disc , index_counter, stackMember
    index_counter = [0]
    stack = []
    # Coloring arrays
    low = [-1] * flow_chart.size
    disc  = [-1] * flow_chart.size
    stackMember = [False] * (flow_chart.size)
    
    result = []
    # Iterating through all block and calculating its strongly connected component
    for block in flow_chart:
        if disc[block.id] == -1:
            SCC_for_current_vertex(block)

    return result 

def Traverse():
    """
    Function traversing all functions returned from ida. Main functionality of the plugin. Performs Tarjans algorithm, density search and outputs search results in a table to stdout
    """

    q = Queue(maxsize = 25)
    counter = 0
    max_counter = 0

    hashmap_of_frequency = {}
    all_non_trivial_loops = []
    # there can be more then one found chunk

    # iterating through all functions returned by ida
    for function_eaddr in idautils.Functions():
        funct_t = ida_funcs.get_func(function_eaddr)

        flow_chart = idaapi.FlowChart(ida_funcs.get_func(function_eaddr))

        first_block = flow_chart[0]

        colors = [0] * flow_chart.size
        parents = [0] * flow_chart.size

        global cyclenumber
        cyclenumber = 0

        
        #Identify loops in graph and output them 

        SCC = tarjan(flow_chart)
        # only taking loops of size > 1
        non_trivial_loops = [component for component in SCC if len(component) > 1]

        # saving all non trivial loops to global array

        for loop in non_trivial_loops:
            all_non_trivial_loops.append(loop)

        # color loops (SCC)
        for loop in non_trivial_loops:
            for block in loop:
                set_color(block.start_ea, 1, 0x00FF00)

        # Counting crypto instruction in each block in the loop
  
        for non_trivial_loop in non_trivial_loops:
            hashmap_of_frequency[non_trivial_loop[0].start_ea] = count_in_loop(non_trivial_loop)

    
    # density search through the whole binary

    density_search_dict = density_search()

    # Reducing overlap between tarjan and density search.

    merged_blocks_dict = find_overlap(all_non_trivial_loops, density_search_dict)
    print(merged_blocks_dict)

    while filtering_results(density_search_dict):
        pass

    # Sorting by value and deleting block with 0 instruction count
    sorted_dict = dict(sorted(hashmap_of_frequency.items(), key=lambda x: x[1]))
    remove_zeros = {k: v for k, v in sorted_dict.items() if v != 0}

    # Making a new table, adding results from loop search first
    myTable = PrettyTable(["Block start address", "Block end address","Function" ,"Crypto instruction count", "Search"])
    for row in remove_zeros:
        myTable.add_row([str(hex(row)),"", ida_funcs.get_func_name(row)[:30] ,remove_zeros[row], "Loop search"])

    # adding results from density search into the table
    for density, blocks in density_search_dict.items():
        for address in blocks:
            myTable.add_row([str(hex(address[0])), str(hex(address[1])),ida_funcs.get_func_name(address[0])[:30] ,density, "Density search"])

    # adding merged blocks 
    for density, merged_block in merged_blocks_dict.items():
        for address in merged_block:
            myTable.add_row([str(hex(address[0])), str(hex(address[1])),ida_funcs.get_func_name(address[0])[:30] ,density, "Merged block"])

    print(myTable)



class CryptoFinder():
    """
    Class handling the search of instructions
    """

    def __init__(self):
        print("CryptoFinder init")
        Traverse()

class CryptoFinderHandler(idaapi.action_handler_t):
    """
    Class handling the actions from menu
    """

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        global Finder
        Finder = CryptoFinder()
    
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class CryptoFinderWrapper(idaapi.plugin_t):
    """
    Main Plugin class
    """
    
    flags = idaapi.PLUGIN_KEEP

    # Naming of the plugin
    action_name = "cf:search"
    comment = 'Cryptographic Finder'
    help = ""
    menu_name = "Find cryptographic instructions"
    wanted_name = "Cryptographic Finder"
    wanted_hotkey = ''
    root_tab = 'Search'

    # registering button as Ctrl+Shift+3 and action in the menu
    def init(self):
        print('CryptoFinderWrapper init')
        action = idaapi.action_desc_t(self.action_name,
                                            self.menu_name,
                                            CryptoFinderHandler(),
                                            'Ctrl-Shift-3',
                                            "",
                                            -1)
        idaapi.register_action(action)
        idaapi.attach_action_to_menu(self.root_tab,self.action_name, idaapi.SETMENU_APP)

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        global Finder
        Finder = CryptoFinder()
        pass

    def term(self):
        idaapi.unregister_action(self.action_name)
        pass


def PLUGIN_ENTRY():
    return CryptoFinderWrapper()
