#define TABLE_LEN 256
#define LEN 5
static unsigned char table[TABLE_LEN] = {0};

void build_table(){
    for(int i=0; i<TABLE_LEN; i++)
        table[i] = i;
}

void nested(unsigned char out[LEN], const unsigned char in[LEN]) {
    
    //reverse in if the first byte is zero
    if(in[0]){
        // mispredict here
        out[0] = table[in[0]];
        out[1] = table[in[1]];
        out[2] = table[in[2]];
        out[3] = table[in[3]];
        out[4] = table[in[4]];
        if(!in[1]){
            // mispredict here
            out[0] = table[in[0]];
            out[1] = 0;
            out[2] = table[in[2]];
            out[3] = table[in[3]];
            out[4] = table[in[4]];
            if(!in[2]){
                // mispredict here
                out[0] = table[in[0]];
                out[1] = table[in[1]];
                out[2] = 0;
                out[3] = table[in[3]];
                out[4] = table[in[4]];
                if(!in[3]){
                    // mispredict here
                    out[0] = table[in[0]];
                    out[1] = table[in[1]];
                    out[2] = 0;
                    out[3] = table[in[3]];
                    out[4] = table[in[4]];
                } else {
                    // mispredict here
                    out[0] = table[in[0]];
                    out[1] = table[in[1]];
                    out[2] = 0xff;
                    out[3] = table[in[3]];
                    out[4] = table[in[4]];
                }                
            } else {
                // mispredict here
                out[0] = table[in[0]];
                out[1] = table[in[1]];
                out[2] = 0xff;
                out[3] = table[in[3]];
                out[4] = table[in[4]];
            }
        } else {
            // mispredict here
            out[0] = table[in[0]];
            out[1] = 0xff;
            out[2] = table[in[2]];
            out[3] = table[in[3]];
            out[4] = table[in[4]];
        }
    } else {
        out[0] = table[in[4]];
        out[1] = table[in[3]];
        out[2] = table[in[2]];
        out[3] = table[in[1]];
        out[4] = table[in[0]];
    }
    if(in[0] > in[1])
        out[0] = 0xff;
    else
        out[4] = 0xff;
}

// no violation is seq but violation in spec
void speculate(unsigned char out[LEN], const unsigned char in[LEN]) {
    
    //reverse in if the first byte is zero
    if(in[0]){
        out[0] = table[in[0]];
        out[1] = table[in[1]];
        out[2] = table[in[2]];
        out[3] = table[in[3]];
        out[4] = table[in[4]];
    } else {
        out[0] = table[in[4]];
        out[1] = table[in[3]];
        out[2] = table[in[2]];
        out[3] = table[in[1]];
        out[4] = table[in[0]];
    }
    if(in[0] > in[1])
        out[0] = 0xff;
    else
        out[4] = 0xff;
}

void call_speculate(){
  build_table();
  unsigned char out[LEN] = {0};
  unsigned char in[LEN] = {0};
  speculate(out,in);
}

void call_nested(){
  build_table();
  unsigned char out[LEN] = {0};
  unsigned char in[LEN] = {0};
  nested(out,in);
}

int main(int argc, char const *argv[])
{
    call_speculate();
    call_nested();
    return 0;
}
