// v shader
attribute vec3 position;
varying   float pos_z;

void main(void){
  gl_Position = vec4(position.xy, 0.0, 1.0);
  pos_z = position.z;
}
  
// f shader
#ifdef GL_ES
precision highp float;
#endif            
varying float pos_z;

float func1 (float arg1, float lo, float hi) { 
    lo = floor(lo + 0.5);
    hi = floor(hi + 0.5); 
    return mod(floor((floor(arg1) + 0.5) / exp2(lo)), floor(1.0*exp2(hi - lo) + 0.5)); 
}

vec4 floatToVec4 (float g) { 
    if (g == 0.0) return vec4(0.0); 
    float a = g > 0.0 ? 0.0 : 1.0; 
    g = abs(g); 
    float b = floor(log2(g)); 
    float v3 = b + 255.0 - 128.0; 
    b = ((g / exp2(b)) - 1.0) * pow(2.0, 23.0);
    float r = v3 / 2.0; 
    v3 = fract(r) + fract(r); 
    float v5 = floor(r); 
    r = func1(b, 0.0, 8.0) / 255.0; 
    g = func1(b, 8.0, 16.0) / 255.0; 
    b = (v3 * 128.0 + func1(b, 16.0, 23.0)) / 255.0; 
    a = (a * 128.0 + v5) / 255.0; 
    return vec4(r, g, b, a); 
}

void main()
{
    gl_FragColor = floatToVec4(pos_z);
}
  