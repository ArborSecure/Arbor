(function(){
  if('scrollRestoration' in history) history.scrollRestoration='manual';
  window.addEventListener('load',function(){window.scrollTo(0,0);});
  var reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  document.getElementById('yr').textContent = new Date().getFullYear();

  // scrolled top bar
  var bar = document.getElementById('bar');
  addEventListener('scroll', function(){ bar.classList.toggle('scrolled', scrollY > 20); }, {passive:true});

  // reveal on scroll
  var io = new IntersectionObserver(function(es){
    es.forEach(function(e){ if(e.isIntersecting){ e.target.classList.add('in'); io.unobserve(e.target);} });
  }, {threshold:.12});
  document.querySelectorAll('.reveal').forEach(function(el){ io.observe(el); });

  // ---------- helpers to draw SVG ----------
  var NS='http://www.w3.org/2000/svg';
  function el(tag,attrs){ var n=document.createElementNS(NS,tag); for(var k in attrs) n.setAttribute(k,attrs[k]); return n; }

  // ---------- HERO TREE (ambient, grows on load) ----------
  (function(){
    var svg=document.getElementById('heroTree'); if(!svg) return;
    // nodes: [id,x,y,parent]
    var N=[
      ['r',230,60,null],
      ['a',120,170,'r'], ['b',340,170,'r'],
      ['c',60,300,'a'], ['d',185,300,'a'],
      ['e',300,300,'b'], ['f',405,300,'b'],
      ['g',40,430,'c'], ['h',130,430,'d'], ['i',245,430,'d'], ['j',355,430,'e'], ['k',430,430,'f']
    ];
    var byId={}; N.forEach(function(n){byId[n[0]]=n;});
    var delay=0;
    // edges first
    N.forEach(function(n){
      if(!n[3]) return; var p=byId[n[3]];
      var path=el('path',{d:'M'+p[1]+' '+p[2]+' L'+n[1]+' '+n[2],stroke:'rgba(52,211,153,.28)','stroke-width':1.4,fill:'none'});
      var len=Math.hypot(n[1]-p[1],n[2]-p[2]);
      if(!reduce){ path.style.strokeDasharray=len; path.style.strokeDashoffset=len; path.style.transition='stroke-dashoffset .6s ease '+(delay)+'s'; }
      svg.appendChild(path);
      requestAnimationFrame(function(){ path.style.strokeDashoffset=0; });
      // travelling pulse
      if(!reduce){
        var pulse=el('circle',{r:2.4,fill:'#34d399',cx:p[1],cy:p[2]});
        pulse.style.filter='drop-shadow(0 0 4px #34d399)';
        svg.appendChild(pulse);
        var am=el('animateMotion',{dur:(2.6+Math.random()*1.6)+'s',repeatCount:'indefinite',begin:(delay+.6)+'s',path:'M0 0 L'+(n[1]-p[1])+' '+(n[2]-p[2])});
        pulse.appendChild(am);
      }
      delay+=0.12;
    });
    // nodes
    delay=0.15;
    N.forEach(function(n){
      var g=el('g',{});
      var isRoot=!n[3];
      var c=el('circle',{cx:n[1],cy:n[2],r:isRoot?9:6.5,fill:isRoot?'#10b981':'#0e3a2c',stroke:'#34d399','stroke-width':isRoot?2:1.4});
      if(!reduce){ c.style.transformOrigin=n[1]+'px '+n[2]+'px'; c.style.transform='scale(0)'; c.style.transition='transform .5s cubic-bezier(.2,1.3,.4,1) '+delay+'s'; }
      g.appendChild(c); svg.appendChild(g);
      requestAnimationFrame(function(){ c.style.transform='scale(1)'; });
      delay+=0.11;
    });
  })();

  // ---------- INTERACTIVE VISIBILITY TREE ----------
  (function(){
    var svg=document.getElementById('visTree'); if(!svg) return;
    // id,x,y,parent,label
    var N=[
      ['root',210,50,null,'You'],
      ['l1a',110,150,'root','Lead'],
      ['l1b',310,150,'root','Lead'],
      ['l2a',60,260,'l1a','Rep'],
      ['l2b',160,260,'l1a','Rep'],
      ['l2c',260,260,'l1b','Rep'],
      ['l2d',360,260,'l1b','Rep'],
      ['l3a',110,370,'l2b','—'],
      ['l3b',310,370,'l2c','—']
    ];
    var byId={}; N.forEach(function(n){byId[n[0]]=n;});
    function depth(id){var d=0,c=byId[id];while(c[3]){d++;c=byId[c[3]];}return d;}
    function isAncestor(a,b){ // is a an ancestor of b
      var c=byId[b]; while(c[3]){ if(c[3]===a) return true; c=byId[c[3]]; } return false;
    }
    // who can `sel` read? self + parent + children + siblings-under-same-parent + ancestors within 2 levels down (oversight of nodes up to 2 below sel)
    function visibleSet(sel){
      var s={}; s[sel]=true;
      var me=byId[sel];
      N.forEach(function(n){
        var id=n[0];
        if(id===sel) return;
        if(me[3]===id) s[id]=true;              // parent
        if(n[3]===sel) s[id]=true;              // child
        if(n[3] && n[3]===me[3]) s[id]=true;    // sibling
        // oversight: sel can read people up to 2 levels below it
        if(isAncestor(sel,id) && (depth(id)-depth(sel))<=2) s[id]=true;
      });
      return s;
    }
    var edges=[];
    N.forEach(function(n){ if(n[3]){ var p=byId[n[3]]; edges.push({a:n[3],b:n[0],p:p,n:n}); } });
    // draw edges
    var edgeEls={};
    edges.forEach(function(e){
      var path=el('path',{class:'edge',d:'M'+e.p[1]+' '+e.p[2]+' L'+e.n[1]+' '+e.n[2]});
      svg.appendChild(path); edgeEls[e.a+'>'+e.b]=path;
    });
    var nodeEls={};
    N.forEach(function(n){
      var g=el('g',{class:'node',tabindex:0,role:'button','aria-label':'Show what '+n[4]+' can read'});
      var ring=el('circle',{class:'ring',cx:n[1],cy:n[2],r:16});
      var c=el('circle',{cx:n[1],cy:n[2],r:n[3]?9:11});
      var t=el('text',{x:n[1],y:n[2]-18,'text-anchor':'middle'}); t.textContent=n[4];
      g.appendChild(ring); g.appendChild(c); g.appendChild(t);
      svg.appendChild(g); nodeEls[n[0]]=g;
      function sel(){ select(n[0]); }
      g.addEventListener('click',sel);
      g.addEventListener('keydown',function(ev){ if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();sel();} });
      g.addEventListener('mouseenter',sel);
    });
    var hint=document.getElementById('visHint');
    function select(sel){
      var vis=visibleSet(sel);
      N.forEach(function(n){
        var g=nodeEls[n[0]]; g.classList.remove('self','see','blind');
        if(n[0]===sel) g.classList.add('self');
        else if(vis[n[0]]) g.classList.add('see');
        else g.classList.add('blind');
      });
      edges.forEach(function(e){
        var lit = (vis[e.a]&&vis[e.b]) || e.a===sel || e.b===sel;
        edgeEls[e.a+'>'+e.b].classList.toggle('lit',lit);
        edgeEls[e.a+'>'+e.b].classList.toggle('dim',!lit);
      });
      var d=depth(sel);
      hint.textContent = d===0
        ? "Even the founder is capped: two levels of oversight, no more."
        : "This person reads their own circle, plus up to two levels below them — nothing higher, nothing sideways across the tree.";
    }
    select('l1a');
  })();

  // ---------- MINI TREES for network types ----------
  function miniTree(id, edges, nodes){
    var svg=document.getElementById(id); if(!svg) return;
    edges.forEach(function(e){ svg.appendChild(el('path',{d:'M'+e[0]+' '+e[1]+' L'+e[2]+' '+e[3],stroke:'rgba(255,255,255,.16)','stroke-width':1.4,fill:'none'})); });
    nodes.forEach(function(n){
      svg.appendChild(el('circle',{cx:n[0],cy:n[1],r:n[2]||8,fill:n[3]||'#0e3a2c',stroke:'#34d399','stroke-width':1.6}));
    });
  }
  // Network: hierarchy
  miniTree('mtNet',
    [[150,40,70,120],[150,40,230,120],[70,120,35,200],[70,120,105,200],[230,120,195,200],[230,120,265,200]],
    [[150,40,11,'#10b981'],[70,120],[230,120],[35,200],[105,200],[195,200],[265,200]]);
  // Direct: hub-and-spoke, root in middle
  miniTree('mtDm',
    [[150,120,60,50],[150,120,240,50],[150,120,50,190],[150,120,250,190],[150,120,150,30],[150,120,150,210]],
    [[150,120,12,'#10b981'],[60,50],[240,50],[50,190],[250,190],[150,30],[150,210]]);
  // Personal: you + a few contacts, loose
  miniTree('mtHub',
    [[150,120,70,70],[150,120,235,80],[150,120,80,180],[150,120,225,175]],
    [[150,120,13,'#10b981'],[70,70],[235,80],[80,180],[225,175]]);

  // network-type tabs
  document.querySelectorAll('.tab').forEach(function(tab){
    tab.addEventListener('click',function(){
      document.querySelectorAll('.tab').forEach(function(t){t.classList.remove('active');t.setAttribute('aria-selected','false');});
      tab.classList.add('active');tab.setAttribute('aria-selected','true');
      var t=tab.dataset.t;
      document.querySelectorAll('.type-panel').forEach(function(p){p.classList.toggle('active',p.dataset.p===t);});
    });
  });

  // ---------- SELF-TYPING CHAT ----------
  (function(){
    var stream=document.getElementById('chatStream'); if(!stream) return;
    // [who, text, mergedWithPrev]
    var script=[
      ['them','42 people signed on so far',false],
      ['them','we file with the board Monday',true],
      ['me',"Let's keep names out of the thread",false],
      ['me',"I'll bring the list in person",true],
      ['them','Good call — see you at 6',false]
    ];
    var i=0;
    function render(){
      if(i>=script.length){ setTimeout(function(){ stream.innerHTML=''; i=0; step(); }, 3200); return; }
      var m=script[i];
      var next=script[i+1];
      var isLastOfRun = !next || next[0]!==m[0] || !next[2];
      var b=document.createElement('div');
      b.className='bubble '+(m[0]==='me'?'b-me':'b-them')+(isLastOfRun?' tail':'');
      b.style.marginTop = m[2] ? '3px' : '10px';
      b.textContent=m[1];
      stream.appendChild(b);
      // keep only last ~7 to avoid overflow
      while(stream.children.length>7) stream.removeChild(stream.firstChild);
      i++;
      setTimeout(render, m[2]?520:900);
    }
    function step(){ render(); }
    // start when visible
    var io2=new IntersectionObserver(function(es){ es.forEach(function(e){ if(e.isIntersecting){ step(); io2.disconnect(); } }); },{threshold:.3});
    io2.observe(stream);
  })();

  // video placeholder — friendly note until embed is wired
  var vs=document.getElementById('videoSlot');
  if(vs){ vs.addEventListener('click',function(){ vs.querySelector('.video-note').textContent='Drop your 4-min video embed here (video/iframe).'; });
    vs.addEventListener('keydown',function(e){ if(e.key==='Enter'||e.key===' '){e.preventDefault();vs.click();} }); }
})();

// ---- Donations (donate section on the landing page) ----
(function(){
  var amts=document.getElementById('donateAmts');
  var custom=document.getElementById('donateCustom');
  var err=document.getElementById('donateErr');
  var cardBtn=document.getElementById('donateCard');
  var cryptoBtn=document.getElementById('donateCrypto');
  if(!amts||!custom) return;
  var selected=20;
  function paint(){ Array.prototype.forEach.call(amts.children,function(b){ b.classList.toggle('sel', !custom.value && Number(b.dataset.amt)===selected); }); }
  Array.prototype.forEach.call(amts.children,function(b){ b.addEventListener('click',function(){ selected=Number(b.dataset.amt); custom.value=''; if(err)err.textContent=''; paint(); }); });
  custom.addEventListener('input',function(){ if(err)err.textContent=''; paint(); });
  paint();
  function amount(){ return custom.value ? parseFloat(custom.value) : selected; }
  var busy=false;
  function go(method,btn){
    if(busy) return;
    var amt=amount();
    if(!(amt>=1&&amt<=10000)){ err.textContent='Enter an amount between $1 and $10,000.'; return; }
    busy=true; err.textContent=''; var label=btn.textContent; btn.textContent='Starting\u2026';
    fetch('/api/donate/'+method,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({amount:amt})})
      .then(function(r){ return r.json().then(function(j){ return {ok:r.ok,j:j}; }); })
      .then(function(res){ if(res.ok&&res.j&&res.j.url){ window.location.href=res.j.url; } else { err.textContent=(res.j&&res.j.error)||'Could not start the donation.'; busy=false; btn.textContent=label; } })
      .catch(function(){ err.textContent='Could not reach the server. Please try again.'; busy=false; btn.textContent=label; });
  }
  if(cardBtn) cardBtn.addEventListener('click',function(){ go('stripe',cardBtn); });
  if(cryptoBtn) cryptoBtn.addEventListener('click',function(){ go('crypto',cryptoBtn); });
  fetch('/api/donate/config').then(function(r){return r.json();}).then(function(c){
    if(c&&c.card===false&&cardBtn) cardBtn.style.display='none';
    if(c&&c.crypto===false&&cryptoBtn) cryptoBtn.style.display='none';
  }).catch(function(){});
  if(location.search.indexOf('donate=thanks')>=0){
    var t=document.createElement('div'); t.className='donate-thanks'; t.textContent='Thank you for supporting Arbor.'; document.body.appendChild(t);
    setTimeout(function(){ t.style.transition='opacity .5s'; t.style.opacity='0'; setTimeout(function(){t.remove();},500); },5000);
  }
})();
