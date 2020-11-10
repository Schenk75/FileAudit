import request from '@/utils/request-test'

export function getList(query) {
  return request({
    url: '/table/open',
    method: 'get',
    params: query
  })
}

export function deleteRecord(query) {
  return request({
    url: '/table/open_delete',
    method: 'get',
    params: query
  })
}