package com.renef.lab;

/**
 * Method slots for Renef's Java hooks.
 *
 * A hooked Java method needs two more method records: a copy that still
 * runs the original code, and a native twin with the same signature that
 * the method's entry point is redirected to. Both have to live where the
 * garbage collector looks for class references, or their reference to the
 * declaring class goes stale as soon as the collector moves that class.
 * The method array of a real class is such a place: each hook takes two of
 * the methods below and overwrites them.
 *
 * The methods are never called as declared here. They are instance methods
 * on purpose: a static method of a class that is not yet "visibly
 * initialized" has the class-resolution entry code instead of its own.
 *
 * Generated file - see scripts/dev/gen_java_slots_dex.sh.
 */
public final class Slots {
    private Slots() {}

    /**
     * Never called. Its frame is too large for ART's fast interpreter (250
     * parameters plus 400 locals that are all alive at once), so its entry
     * point is the plain interpreter bridge - which is how the agent learns
     * that address. The parameters alone are not enough: in an app that is
     * not debuggable such a method still ran in the fast interpreter. The
     * bridge can run any method from its bytecode, and it is what a copy of
     * a hooked method is pointed at when the original's own entry point was
     * JIT-compiled code (ART may free that code later).
     */
    public int interpreted(int p0, int p1, int p2, int p3, int p4, int p5, int p6, int p7, int p8, int p9, int p10, int p11, int p12, int p13, int p14, int p15, int p16, int p17, int p18, int p19, int p20, int p21, int p22, int p23, int p24, int p25, int p26, int p27, int p28, int p29, int p30, int p31, int p32, int p33, int p34, int p35, int p36, int p37, int p38, int p39, int p40, int p41, int p42, int p43, int p44, int p45, int p46, int p47, int p48, int p49, int p50, int p51, int p52, int p53, int p54, int p55, int p56, int p57, int p58, int p59, int p60, int p61, int p62, int p63, int p64, int p65, int p66, int p67, int p68, int p69, int p70, int p71, int p72, int p73, int p74, int p75, int p76, int p77, int p78, int p79, int p80, int p81, int p82, int p83, int p84, int p85, int p86, int p87, int p88, int p89, int p90, int p91, int p92, int p93, int p94, int p95, int p96, int p97, int p98, int p99, int p100, int p101, int p102, int p103, int p104, int p105, int p106, int p107, int p108, int p109, int p110, int p111, int p112, int p113, int p114, int p115, int p116, int p117, int p118, int p119, int p120, int p121, int p122, int p123, int p124, int p125, int p126, int p127, int p128, int p129, int p130, int p131, int p132, int p133, int p134, int p135, int p136, int p137, int p138, int p139, int p140, int p141, int p142, int p143, int p144, int p145, int p146, int p147, int p148, int p149, int p150, int p151, int p152, int p153, int p154, int p155, int p156, int p157, int p158, int p159, int p160, int p161, int p162, int p163, int p164, int p165, int p166, int p167, int p168, int p169, int p170, int p171, int p172, int p173, int p174, int p175, int p176, int p177, int p178, int p179, int p180, int p181, int p182, int p183, int p184, int p185, int p186, int p187, int p188, int p189, int p190, int p191, int p192, int p193, int p194, int p195, int p196, int p197, int p198, int p199, int p200, int p201, int p202, int p203, int p204, int p205, int p206, int p207, int p208, int p209, int p210, int p211, int p212, int p213, int p214, int p215, int p216, int p217, int p218, int p219, int p220, int p221, int p222, int p223, int p224, int p225, int p226, int p227, int p228, int p229, int p230, int p231, int p232, int p233, int p234, int p235, int p236, int p237, int p238, int p239, int p240, int p241, int p242, int p243, int p244, int p245, int p246, int p247, int p248, int p249) {
        int a0 = p0 ^ 1; int a1 = p1 ^ 2; int a2 = p2 ^ 3; int a3 = p3 ^ 4; int a4 = p4 ^ 5; int a5 = p5 ^ 6; int a6 = p6 ^ 7; int a7 = p7 ^ 8;
        int a8 = p8 ^ 9; int a9 = p9 ^ 10; int a10 = p10 ^ 11; int a11 = p11 ^ 12; int a12 = p12 ^ 13; int a13 = p13 ^ 14; int a14 = p14 ^ 15; int a15 = p15 ^ 16;
        int a16 = p16 ^ 17; int a17 = p17 ^ 18; int a18 = p18 ^ 19; int a19 = p19 ^ 20; int a20 = p20 ^ 21; int a21 = p21 ^ 22; int a22 = p22 ^ 23; int a23 = p23 ^ 24;
        int a24 = p24 ^ 25; int a25 = p25 ^ 26; int a26 = p26 ^ 27; int a27 = p27 ^ 28; int a28 = p28 ^ 29; int a29 = p29 ^ 30; int a30 = p30 ^ 31; int a31 = p31 ^ 32;
        int a32 = p32 ^ 33; int a33 = p33 ^ 34; int a34 = p34 ^ 35; int a35 = p35 ^ 36; int a36 = p36 ^ 37; int a37 = p37 ^ 38; int a38 = p38 ^ 39; int a39 = p39 ^ 40;
        int a40 = p40 ^ 41; int a41 = p41 ^ 42; int a42 = p42 ^ 43; int a43 = p43 ^ 44; int a44 = p44 ^ 45; int a45 = p45 ^ 46; int a46 = p46 ^ 47; int a47 = p47 ^ 48;
        int a48 = p48 ^ 49; int a49 = p49 ^ 50; int a50 = p50 ^ 51; int a51 = p51 ^ 52; int a52 = p52 ^ 53; int a53 = p53 ^ 54; int a54 = p54 ^ 55; int a55 = p55 ^ 56;
        int a56 = p56 ^ 57; int a57 = p57 ^ 58; int a58 = p58 ^ 59; int a59 = p59 ^ 60; int a60 = p60 ^ 61; int a61 = p61 ^ 62; int a62 = p62 ^ 63; int a63 = p63 ^ 64;
        int a64 = p64 ^ 65; int a65 = p65 ^ 66; int a66 = p66 ^ 67; int a67 = p67 ^ 68; int a68 = p68 ^ 69; int a69 = p69 ^ 70; int a70 = p70 ^ 71; int a71 = p71 ^ 72;
        int a72 = p72 ^ 73; int a73 = p73 ^ 74; int a74 = p74 ^ 75; int a75 = p75 ^ 76; int a76 = p76 ^ 77; int a77 = p77 ^ 78; int a78 = p78 ^ 79; int a79 = p79 ^ 80;
        int a80 = p80 ^ 81; int a81 = p81 ^ 82; int a82 = p82 ^ 83; int a83 = p83 ^ 84; int a84 = p84 ^ 85; int a85 = p85 ^ 86; int a86 = p86 ^ 87; int a87 = p87 ^ 88;
        int a88 = p88 ^ 89; int a89 = p89 ^ 90; int a90 = p90 ^ 91; int a91 = p91 ^ 92; int a92 = p92 ^ 93; int a93 = p93 ^ 94; int a94 = p94 ^ 95; int a95 = p95 ^ 96;
        int a96 = p96 ^ 97; int a97 = p97 ^ 98; int a98 = p98 ^ 99; int a99 = p99 ^ 100; int a100 = p100 ^ 101; int a101 = p101 ^ 102; int a102 = p102 ^ 103; int a103 = p103 ^ 104;
        int a104 = p104 ^ 105; int a105 = p105 ^ 106; int a106 = p106 ^ 107; int a107 = p107 ^ 108; int a108 = p108 ^ 109; int a109 = p109 ^ 110; int a110 = p110 ^ 111; int a111 = p111 ^ 112;
        int a112 = p112 ^ 113; int a113 = p113 ^ 114; int a114 = p114 ^ 115; int a115 = p115 ^ 116; int a116 = p116 ^ 117; int a117 = p117 ^ 118; int a118 = p118 ^ 119; int a119 = p119 ^ 120;
        int a120 = p120 ^ 121; int a121 = p121 ^ 122; int a122 = p122 ^ 123; int a123 = p123 ^ 124; int a124 = p124 ^ 125; int a125 = p125 ^ 126; int a126 = p126 ^ 127; int a127 = p127 ^ 128;
        int a128 = p128 ^ 129; int a129 = p129 ^ 130; int a130 = p130 ^ 131; int a131 = p131 ^ 132; int a132 = p132 ^ 133; int a133 = p133 ^ 134; int a134 = p134 ^ 135; int a135 = p135 ^ 136;
        int a136 = p136 ^ 137; int a137 = p137 ^ 138; int a138 = p138 ^ 139; int a139 = p139 ^ 140; int a140 = p140 ^ 141; int a141 = p141 ^ 142; int a142 = p142 ^ 143; int a143 = p143 ^ 144;
        int a144 = p144 ^ 145; int a145 = p145 ^ 146; int a146 = p146 ^ 147; int a147 = p147 ^ 148; int a148 = p148 ^ 149; int a149 = p149 ^ 150; int a150 = p150 ^ 151; int a151 = p151 ^ 152;
        int a152 = p152 ^ 153; int a153 = p153 ^ 154; int a154 = p154 ^ 155; int a155 = p155 ^ 156; int a156 = p156 ^ 157; int a157 = p157 ^ 158; int a158 = p158 ^ 159; int a159 = p159 ^ 160;
        int a160 = p160 ^ 161; int a161 = p161 ^ 162; int a162 = p162 ^ 163; int a163 = p163 ^ 164; int a164 = p164 ^ 165; int a165 = p165 ^ 166; int a166 = p166 ^ 167; int a167 = p167 ^ 168;
        int a168 = p168 ^ 169; int a169 = p169 ^ 170; int a170 = p170 ^ 171; int a171 = p171 ^ 172; int a172 = p172 ^ 173; int a173 = p173 ^ 174; int a174 = p174 ^ 175; int a175 = p175 ^ 176;
        int a176 = p176 ^ 177; int a177 = p177 ^ 178; int a178 = p178 ^ 179; int a179 = p179 ^ 180; int a180 = p180 ^ 181; int a181 = p181 ^ 182; int a182 = p182 ^ 183; int a183 = p183 ^ 184;
        int a184 = p184 ^ 185; int a185 = p185 ^ 186; int a186 = p186 ^ 187; int a187 = p187 ^ 188; int a188 = p188 ^ 189; int a189 = p189 ^ 190; int a190 = p190 ^ 191; int a191 = p191 ^ 192;
        int a192 = p192 ^ 193; int a193 = p193 ^ 194; int a194 = p194 ^ 195; int a195 = p195 ^ 196; int a196 = p196 ^ 197; int a197 = p197 ^ 198; int a198 = p198 ^ 199; int a199 = p199 ^ 200;
        int a200 = p200 ^ 201; int a201 = p201 ^ 202; int a202 = p202 ^ 203; int a203 = p203 ^ 204; int a204 = p204 ^ 205; int a205 = p205 ^ 206; int a206 = p206 ^ 207; int a207 = p207 ^ 208;
        int a208 = p208 ^ 209; int a209 = p209 ^ 210; int a210 = p210 ^ 211; int a211 = p211 ^ 212; int a212 = p212 ^ 213; int a213 = p213 ^ 214; int a214 = p214 ^ 215; int a215 = p215 ^ 216;
        int a216 = p216 ^ 217; int a217 = p217 ^ 218; int a218 = p218 ^ 219; int a219 = p219 ^ 220; int a220 = p220 ^ 221; int a221 = p221 ^ 222; int a222 = p222 ^ 223; int a223 = p223 ^ 224;
        int a224 = p224 ^ 225; int a225 = p225 ^ 226; int a226 = p226 ^ 227; int a227 = p227 ^ 228; int a228 = p228 ^ 229; int a229 = p229 ^ 230; int a230 = p230 ^ 231; int a231 = p231 ^ 232;
        int a232 = p232 ^ 233; int a233 = p233 ^ 234; int a234 = p234 ^ 235; int a235 = p235 ^ 236; int a236 = p236 ^ 237; int a237 = p237 ^ 238; int a238 = p238 ^ 239; int a239 = p239 ^ 240;
        int a240 = p240 ^ 241; int a241 = p241 ^ 242; int a242 = p242 ^ 243; int a243 = p243 ^ 244; int a244 = p244 ^ 245; int a245 = p245 ^ 246; int a246 = p246 ^ 247; int a247 = p247 ^ 248;
        int a248 = p248 ^ 249; int a249 = p249 ^ 250; int a250 = p0 ^ 251; int a251 = p1 ^ 252; int a252 = p2 ^ 253; int a253 = p3 ^ 254; int a254 = p4 ^ 255; int a255 = p5 ^ 256;
        int a256 = p6 ^ 257; int a257 = p7 ^ 258; int a258 = p8 ^ 259; int a259 = p9 ^ 260; int a260 = p10 ^ 261; int a261 = p11 ^ 262; int a262 = p12 ^ 263; int a263 = p13 ^ 264;
        int a264 = p14 ^ 265; int a265 = p15 ^ 266; int a266 = p16 ^ 267; int a267 = p17 ^ 268; int a268 = p18 ^ 269; int a269 = p19 ^ 270; int a270 = p20 ^ 271; int a271 = p21 ^ 272;
        int a272 = p22 ^ 273; int a273 = p23 ^ 274; int a274 = p24 ^ 275; int a275 = p25 ^ 276; int a276 = p26 ^ 277; int a277 = p27 ^ 278; int a278 = p28 ^ 279; int a279 = p29 ^ 280;
        int a280 = p30 ^ 281; int a281 = p31 ^ 282; int a282 = p32 ^ 283; int a283 = p33 ^ 284; int a284 = p34 ^ 285; int a285 = p35 ^ 286; int a286 = p36 ^ 287; int a287 = p37 ^ 288;
        int a288 = p38 ^ 289; int a289 = p39 ^ 290; int a290 = p40 ^ 291; int a291 = p41 ^ 292; int a292 = p42 ^ 293; int a293 = p43 ^ 294; int a294 = p44 ^ 295; int a295 = p45 ^ 296;
        int a296 = p46 ^ 297; int a297 = p47 ^ 298; int a298 = p48 ^ 299; int a299 = p49 ^ 300; int a300 = p50 ^ 301; int a301 = p51 ^ 302; int a302 = p52 ^ 303; int a303 = p53 ^ 304;
        int a304 = p54 ^ 305; int a305 = p55 ^ 306; int a306 = p56 ^ 307; int a307 = p57 ^ 308; int a308 = p58 ^ 309; int a309 = p59 ^ 310; int a310 = p60 ^ 311; int a311 = p61 ^ 312;
        int a312 = p62 ^ 313; int a313 = p63 ^ 314; int a314 = p64 ^ 315; int a315 = p65 ^ 316; int a316 = p66 ^ 317; int a317 = p67 ^ 318; int a318 = p68 ^ 319; int a319 = p69 ^ 320;
        int a320 = p70 ^ 321; int a321 = p71 ^ 322; int a322 = p72 ^ 323; int a323 = p73 ^ 324; int a324 = p74 ^ 325; int a325 = p75 ^ 326; int a326 = p76 ^ 327; int a327 = p77 ^ 328;
        int a328 = p78 ^ 329; int a329 = p79 ^ 330; int a330 = p80 ^ 331; int a331 = p81 ^ 332; int a332 = p82 ^ 333; int a333 = p83 ^ 334; int a334 = p84 ^ 335; int a335 = p85 ^ 336;
        int a336 = p86 ^ 337; int a337 = p87 ^ 338; int a338 = p88 ^ 339; int a339 = p89 ^ 340; int a340 = p90 ^ 341; int a341 = p91 ^ 342; int a342 = p92 ^ 343; int a343 = p93 ^ 344;
        int a344 = p94 ^ 345; int a345 = p95 ^ 346; int a346 = p96 ^ 347; int a347 = p97 ^ 348; int a348 = p98 ^ 349; int a349 = p99 ^ 350; int a350 = p100 ^ 351; int a351 = p101 ^ 352;
        int a352 = p102 ^ 353; int a353 = p103 ^ 354; int a354 = p104 ^ 355; int a355 = p105 ^ 356; int a356 = p106 ^ 357; int a357 = p107 ^ 358; int a358 = p108 ^ 359; int a359 = p109 ^ 360;
        int a360 = p110 ^ 361; int a361 = p111 ^ 362; int a362 = p112 ^ 363; int a363 = p113 ^ 364; int a364 = p114 ^ 365; int a365 = p115 ^ 366; int a366 = p116 ^ 367; int a367 = p117 ^ 368;
        int a368 = p118 ^ 369; int a369 = p119 ^ 370; int a370 = p120 ^ 371; int a371 = p121 ^ 372; int a372 = p122 ^ 373; int a373 = p123 ^ 374; int a374 = p124 ^ 375; int a375 = p125 ^ 376;
        int a376 = p126 ^ 377; int a377 = p127 ^ 378; int a378 = p128 ^ 379; int a379 = p129 ^ 380; int a380 = p130 ^ 381; int a381 = p131 ^ 382; int a382 = p132 ^ 383; int a383 = p133 ^ 384;
        int a384 = p134 ^ 385; int a385 = p135 ^ 386; int a386 = p136 ^ 387; int a387 = p137 ^ 388; int a388 = p138 ^ 389; int a389 = p139 ^ 390; int a390 = p140 ^ 391; int a391 = p141 ^ 392;
        int a392 = p142 ^ 393; int a393 = p143 ^ 394; int a394 = p144 ^ 395; int a395 = p145 ^ 396; int a396 = p146 ^ 397; int a397 = p147 ^ 398; int a398 = p148 ^ 399; int a399 = p149 ^ 400;
        return a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9 + a10 + a11 + a12 + a13 + a14 + a15
            + a16 + a17 + a18 + a19 + a20 + a21 + a22 + a23 + a24 + a25 + a26 + a27 + a28 + a29 + a30 + a31
            + a32 + a33 + a34 + a35 + a36 + a37 + a38 + a39 + a40 + a41 + a42 + a43 + a44 + a45 + a46 + a47
            + a48 + a49 + a50 + a51 + a52 + a53 + a54 + a55 + a56 + a57 + a58 + a59 + a60 + a61 + a62 + a63
            + a64 + a65 + a66 + a67 + a68 + a69 + a70 + a71 + a72 + a73 + a74 + a75 + a76 + a77 + a78 + a79
            + a80 + a81 + a82 + a83 + a84 + a85 + a86 + a87 + a88 + a89 + a90 + a91 + a92 + a93 + a94 + a95
            + a96 + a97 + a98 + a99 + a100 + a101 + a102 + a103 + a104 + a105 + a106 + a107 + a108 + a109 + a110 + a111
            + a112 + a113 + a114 + a115 + a116 + a117 + a118 + a119 + a120 + a121 + a122 + a123 + a124 + a125 + a126 + a127
            + a128 + a129 + a130 + a131 + a132 + a133 + a134 + a135 + a136 + a137 + a138 + a139 + a140 + a141 + a142 + a143
            + a144 + a145 + a146 + a147 + a148 + a149 + a150 + a151 + a152 + a153 + a154 + a155 + a156 + a157 + a158 + a159
            + a160 + a161 + a162 + a163 + a164 + a165 + a166 + a167 + a168 + a169 + a170 + a171 + a172 + a173 + a174 + a175
            + a176 + a177 + a178 + a179 + a180 + a181 + a182 + a183 + a184 + a185 + a186 + a187 + a188 + a189 + a190 + a191
            + a192 + a193 + a194 + a195 + a196 + a197 + a198 + a199 + a200 + a201 + a202 + a203 + a204 + a205 + a206 + a207
            + a208 + a209 + a210 + a211 + a212 + a213 + a214 + a215 + a216 + a217 + a218 + a219 + a220 + a221 + a222 + a223
            + a224 + a225 + a226 + a227 + a228 + a229 + a230 + a231 + a232 + a233 + a234 + a235 + a236 + a237 + a238 + a239
            + a240 + a241 + a242 + a243 + a244 + a245 + a246 + a247 + a248 + a249 + a250 + a251 + a252 + a253 + a254 + a255
            + a256 + a257 + a258 + a259 + a260 + a261 + a262 + a263 + a264 + a265 + a266 + a267 + a268 + a269 + a270 + a271
            + a272 + a273 + a274 + a275 + a276 + a277 + a278 + a279 + a280 + a281 + a282 + a283 + a284 + a285 + a286 + a287
            + a288 + a289 + a290 + a291 + a292 + a293 + a294 + a295 + a296 + a297 + a298 + a299 + a300 + a301 + a302 + a303
            + a304 + a305 + a306 + a307 + a308 + a309 + a310 + a311 + a312 + a313 + a314 + a315 + a316 + a317 + a318 + a319
            + a320 + a321 + a322 + a323 + a324 + a325 + a326 + a327 + a328 + a329 + a330 + a331 + a332 + a333 + a334 + a335
            + a336 + a337 + a338 + a339 + a340 + a341 + a342 + a343 + a344 + a345 + a346 + a347 + a348 + a349 + a350 + a351
            + a352 + a353 + a354 + a355 + a356 + a357 + a358 + a359 + a360 + a361 + a362 + a363 + a364 + a365 + a366 + a367
            + a368 + a369 + a370 + a371 + a372 + a373 + a374 + a375 + a376 + a377 + a378 + a379 + a380 + a381 + a382 + a383
            + a384 + a385 + a386 + a387 + a388 + a389 + a390 + a391 + a392 + a393 + a394 + a395 + a396 + a397 + a398 + a399;
    }

    /**
     * Never called. These two tell the agent where ART's generic JNI entry
     * code is: that is the entry point of a native method for which ART has
     * no compiled stub. The slot methods below cannot be used for that - in
     * an app that is not debuggable ART gives a native method the stub the
     * boot image already holds for the same kind of signature, and
     * "instance method, no arguments, void" certainly has one. Nothing in
     * the boot image has signatures like these two, and they differ from
     * each other, so an entry point they share is the generic one.
     */
    public native double probeA(double a, long b, float c, int d, Object e, double f, long g, float h, int i, Object j,
                                double k, long l, float m, int n, Object o, short p, byte q, char r, boolean s, double t, long u);
    public native long probeB(Object a, float b, long c, double d, int e, Object f, float g, long h, double i, int j,
                              char k, short l, byte m, boolean n, Object o, float p, long q, double r, int s);

    public native void s0();
    public native void s1();
    public native void s2();
    public native void s3();
    public native void s4();
    public native void s5();
    public native void s6();
    public native void s7();
    public native void s8();
    public native void s9();
    public native void s10();
    public native void s11();
    public native void s12();
    public native void s13();
    public native void s14();
    public native void s15();
    public native void s16();
    public native void s17();
    public native void s18();
    public native void s19();
    public native void s20();
    public native void s21();
    public native void s22();
    public native void s23();
    public native void s24();
    public native void s25();
    public native void s26();
    public native void s27();
    public native void s28();
    public native void s29();
    public native void s30();
    public native void s31();
    public native void s32();
    public native void s33();
    public native void s34();
    public native void s35();
    public native void s36();
    public native void s37();
    public native void s38();
    public native void s39();
    public native void s40();
    public native void s41();
    public native void s42();
    public native void s43();
    public native void s44();
    public native void s45();
    public native void s46();
    public native void s47();
    public native void s48();
    public native void s49();
    public native void s50();
    public native void s51();
    public native void s52();
    public native void s53();
    public native void s54();
    public native void s55();
    public native void s56();
    public native void s57();
    public native void s58();
    public native void s59();
    public native void s60();
    public native void s61();
    public native void s62();
    public native void s63();
    public native void s64();
    public native void s65();
    public native void s66();
    public native void s67();
    public native void s68();
    public native void s69();
    public native void s70();
    public native void s71();
    public native void s72();
    public native void s73();
    public native void s74();
    public native void s75();
    public native void s76();
    public native void s77();
    public native void s78();
    public native void s79();
    public native void s80();
    public native void s81();
    public native void s82();
    public native void s83();
    public native void s84();
    public native void s85();
    public native void s86();
    public native void s87();
    public native void s88();
    public native void s89();
    public native void s90();
    public native void s91();
    public native void s92();
    public native void s93();
    public native void s94();
    public native void s95();
    public native void s96();
    public native void s97();
    public native void s98();
    public native void s99();
    public native void s100();
    public native void s101();
    public native void s102();
    public native void s103();
    public native void s104();
    public native void s105();
    public native void s106();
    public native void s107();
    public native void s108();
    public native void s109();
    public native void s110();
    public native void s111();
    public native void s112();
    public native void s113();
    public native void s114();
    public native void s115();
    public native void s116();
    public native void s117();
    public native void s118();
    public native void s119();
    public native void s120();
    public native void s121();
    public native void s122();
    public native void s123();
    public native void s124();
    public native void s125();
    public native void s126();
    public native void s127();
    public native void s128();
    public native void s129();
    public native void s130();
    public native void s131();
    public native void s132();
    public native void s133();
    public native void s134();
    public native void s135();
    public native void s136();
    public native void s137();
    public native void s138();
    public native void s139();
    public native void s140();
    public native void s141();
    public native void s142();
    public native void s143();
    public native void s144();
    public native void s145();
    public native void s146();
    public native void s147();
    public native void s148();
    public native void s149();
    public native void s150();
    public native void s151();
    public native void s152();
    public native void s153();
    public native void s154();
    public native void s155();
    public native void s156();
    public native void s157();
    public native void s158();
    public native void s159();
    public native void s160();
    public native void s161();
    public native void s162();
    public native void s163();
    public native void s164();
    public native void s165();
    public native void s166();
    public native void s167();
    public native void s168();
    public native void s169();
    public native void s170();
    public native void s171();
    public native void s172();
    public native void s173();
    public native void s174();
    public native void s175();
    public native void s176();
    public native void s177();
    public native void s178();
    public native void s179();
    public native void s180();
    public native void s181();
    public native void s182();
    public native void s183();
    public native void s184();
    public native void s185();
    public native void s186();
    public native void s187();
    public native void s188();
    public native void s189();
    public native void s190();
    public native void s191();
    public native void s192();
    public native void s193();
    public native void s194();
    public native void s195();
    public native void s196();
    public native void s197();
    public native void s198();
    public native void s199();
    public native void s200();
    public native void s201();
    public native void s202();
    public native void s203();
    public native void s204();
    public native void s205();
    public native void s206();
    public native void s207();
    public native void s208();
    public native void s209();
    public native void s210();
    public native void s211();
    public native void s212();
    public native void s213();
    public native void s214();
    public native void s215();
    public native void s216();
    public native void s217();
    public native void s218();
    public native void s219();
    public native void s220();
    public native void s221();
    public native void s222();
    public native void s223();
    public native void s224();
    public native void s225();
    public native void s226();
    public native void s227();
    public native void s228();
    public native void s229();
    public native void s230();
    public native void s231();
    public native void s232();
    public native void s233();
    public native void s234();
    public native void s235();
    public native void s236();
    public native void s237();
    public native void s238();
    public native void s239();
    public native void s240();
    public native void s241();
    public native void s242();
    public native void s243();
    public native void s244();
    public native void s245();
    public native void s246();
    public native void s247();
    public native void s248();
    public native void s249();
    public native void s250();
    public native void s251();
    public native void s252();
    public native void s253();
    public native void s254();
    public native void s255();
}
