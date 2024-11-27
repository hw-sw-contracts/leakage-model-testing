import sys
import glob
with open(r'res/'+sys.argv[3], 'w') as clear_file:
    clear_file.write("")
with open(r'res/'+sys.argv[3], 'a') as write_file:
    write_file.write(sys.argv[1]+", ct, ss, ssi, ssi0, rfc, rfc0, nrfc, cs, cst, ncs, op, cr, cra, cc-fpc, cc-bdi, pf-nl, pf-stream, pf-m1, \n")
    for f in glob.glob('./res/*'+sys.argv[1]+'*'+sys.argv[2]+'*.csv'): # do_something
        with open(f, 'r') as read_file:
            if "all" in f:
                continue
            line = read_file.readlines()[1]
            if line[-1] != '\n':
                line += '\n'
            write_file.write(line)

