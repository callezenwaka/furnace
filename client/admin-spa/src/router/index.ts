import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from '../views/Dashboard.vue'
import Users from '../views/Users.vue'
import Groups from '../views/Groups.vue'
import Sessions from '../views/Sessions.vue'

const router = createRouter({
  history: createWebHistory('/admin/'),
  routes: [
    { path: '/',         component: Dashboard },
    { path: '/users',    component: Users },
    { path: '/groups',   component: Groups },
    { path: '/sessions', component: Sessions },
  ],
})

export default router
