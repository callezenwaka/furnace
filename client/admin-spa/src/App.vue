<template>
  <div>
    <span>
      <img src="/vite.svg" class="logo" alt="Vite logo" />
    </span>
    <span>
      <img src="./assets/vue.svg" class="logo vue" alt="Vue logo" />
    </span>
  </div>
  <Authpilot msg="Auth Pilot" />
</template>

<script setup lang="ts">
import Authpilot from './components/Authpilot.vue'
</script>

<style scoped>
.logo {
  height: 6em;
  padding: 1.5em;
  will-change: filter;
  rotate: 180deg;
  transition: filter 300ms;
}
.logo:hover {
  filter: drop-shadow(0 0 2em #646cffaa);
}
.logo.vue:hover {
  filter: drop-shadow(0 0 2em #42b883aa);
}
</style>
