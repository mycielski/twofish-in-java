package twofish;

import static twofish.Constants.*;

//TODO javadoc
class MDSMatrixCalculations {
    static {

        //
        // precompute the MDS matrix
        //
        int[] m1 = new int[2];
        int[] mX = new int[2];
        int[] mY = new int[2];
        int i, j;
        for (i = 0; i < 256; i++) {
            j = P[0][i] & 0xFF; // compute all the matrix elements
            m1[0] = j;
            mX[0] = Mx_X(j) & 0xFF;
            mY[0] = Mx_Y(j) & 0xFF;

            j = P[1][i] & 0xFF;
            m1[1] = j;
            mX[1] = Mx_X(j) & 0xFF;
            mY[1] = Mx_Y(j) & 0xFF;

            // fill matrix w/ above elements
            MDS[0][i] = m1[P_00] | mX[P_00] << 8 | mY[P_00] << 16 | mY[P_00] << 24;
            MDS[1][i] = mY[P_10] | mY[P_10] << 8 | mX[P_10] << 16 | m1[P_10] << 24;
            MDS[2][i] = mX[P_20] | mY[P_20] << 8 | m1[P_20] << 16 | mY[P_20] << 24;
            MDS[3][i] = mX[P_30] | m1[P_30] << 8 | mY[P_30] << 16 | mX[P_30] << 24;
        }


    }


// Static code - to intialise the MDS matrix
//...........................................................................


    private static int LFSR1(int x) {
        return (x >> 1) ^
                ((x & 0x01) != 0 ? GF256_FDBK_2 : 0);
    }

    private static int LFSR2(int x) {
        return (x >> 2) ^
                ((x & 0x02) != 0 ? GF256_FDBK_2 : 0) ^
                ((x & 0x01) != 0 ? GF256_FDBK_4 : 0);
    }

    private static int Mx_X(int x) {
        return x ^ LFSR2(x);
    }            // 5B

    private static int Mx_Y(int x) {
        return x ^ LFSR1(x) ^ LFSR2(x);
    } // EF

}
